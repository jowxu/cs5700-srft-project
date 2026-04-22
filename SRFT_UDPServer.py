import socket
import sys
import os
import threading
import time
import hmac
import hashlib
import secrets
from SRFT_Config import SERVER_IP, SERVER_PORT, PSK
from SRFT_Utils import TYPE_DATA, TYPE_ACK, TYPE_REQ, TYPE_FIN, build_packet, parse_packet, parse_client_hello, confirm_checksum, calc_file_hashes
from Security import encrypt_payload, decrypt_payload
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Sliding window specifications
WINDOW_SIZE  = 64
TIMEOUT = 2.0
CHUNK_SIZE = 1024  # size of each file chunk to send (in bytes)

class SRFT_UDPServer:
    def __init__(self):
        self.stats = {
            "filename": "",
            "filesize": 0,
            "packets_sent": 0,
            "retransmitted": 0,
            "received_from_client": 0,
            "start_time": 0,
            "original_file_md5": "",
        }

        # config server port and ip
        self.server_port = SERVER_PORT
        self.server_ip = SERVER_IP

        try:
            # Using IPPROTO_RAW to manually build IP headers
            self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            # receiver socket (used to receive incoming UDP packets)
            self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except PermissionError:
            print("Error: Root privileges required.")
            exit(1)

        self.unacked     = {}   # {seq_num: {"packet": bytes, "sent_time": float}}
        self.base        = 1    # left edge of the window — the next ACK we expect
        self.window_lock = threading.Lock() 
        self.transfer_done = threading.Event() # Event that listen_for_acks() sets when the transfer is fully acknowledged
        self.dest_port = 0          # client port
        self.total_packets = 0      # total number of file chunks 
        self.ack_thread = None
        self.last_ack_num = 0
        self.dup_ack_count = 0
        self.dest_ip = None

        # attack mode fields
        self.attack_mode = None
        # tamper fields
        self.has_tampered = False
        # replay fields
        self.replay_packet = None
        self.replay_seq = None
        self.replay_sent = False
        # inject fields
        self.inject_sent = False
        self.inject_seq = None

    def handshake(self):
        # return boolean and enc_key
        handshake_confirmed = False
        while True: 
            # wait for client hello
            raw_bytes, client_address = self.recv_sock.recvfrom(1024)
            # need to check if the packet is for this server
            src_ip, dst_ip, src_port, dst_port, p_type, checksum, seq, ack, payload = parse_packet(raw_bytes)
            if dst_port != self.server_port:
                continue

            if p_type != TYPE_REQ:
                continue

            if not confirm_checksum(p_type, checksum, seq, ack, payload):
                print("[SERVER] Handshake packet checksum mismatch")
                continue

            nonce_client, protocol_version, hmac_client = parse_client_hello(raw_bytes)
            client_msg = nonce_client + protocol_version
            # verify hmac value matches
            hmac_calc = hmac.digest(PSK, client_msg, hashlib.sha256)
            verified = hmac.compare_digest(hmac_client, hmac_calc)
            if (verified is False):  
                print("[SERVER] Handshake HMAC verification failed")
                return False, None, None   
            
            handshake_confirmed = True
            # send server hello to client 
            nonce_server = secrets.token_bytes(16)
            session_id = secrets.token_bytes(8)

            server_msg = nonce_server + session_id
            hmac_server = hmac.digest(PSK, server_msg, hashlib.sha256)
            hello_payload = nonce_server + session_id + hmac_server
            hello_packet = build_packet(
                data=hello_payload,
                seq_num=0,
                ack_num=0,
                src_ip=self.server_ip,
                dst_ip=client_address[0],
                src_port=self.server_port,
                dst_port=src_port,
                p_type=TYPE_ACK
            )

            self.send_sock.sendto(hello_packet, (client_address[0], 0))
            # derive session key with HKDF use as enc_key
            hkdf_input = PSK + nonce_client + nonce_server + session_id
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'')
            enc_key = hkdf.derive(hkdf_input)

            return handshake_confirmed, enc_key, session_id

    def wait_for_request(self):
        """
        wait for a client request packet. (Currently payload will just be filename).
        return: filename, src_ip, src_port
        """
        while True:
            # wait for packet
            raw_bytes, address = self.recv_sock.recvfrom(65535) #returns tuple, address redundant so ignore it

            # parse packet and fill in variables
            src_ip, dst_ip, src_port, dst_port, p_type, checksum, seq, ack, payload = parse_packet(raw_bytes)

            # If port and server port dont match, ignore packet
            if dst_port != self.server_port:
                continue

            # ignore non req packet types
            if p_type != TYPE_REQ:
                continue

            # discard if checksum doesnt match
            if not confirm_checksum(p_type, checksum, seq, ack, payload):
                print(f"[SERVER] Checksum mismatch: corrupted REQ packet seq={seq} discarded")
                continue
            
            # check type, make sure it is a request type packet
            if p_type == TYPE_REQ:
                #convert payload from bytes to string
                payload_string = payload.decode(errors="ignore").strip()

                print(f"received file request: '{payload_string}' from {src_ip}:{src_port}")

                return payload_string, src_ip, src_port
    
    def start_ack_thread(self):
        """
        helper function that starts the thread that listens for ack.
        """
        self.transfer_done.clear()
        self.ack_thread = threading.Thread(target=self.listen_for_acks, daemon=True)
        self.ack_thread.start()

    def stop_ack_thread(self):
        """
        helper function that stops the thread that listens for ack.
        """
        self.transfer_done.set()

        if self.ack_thread is not None:
            self.ack_thread.join(timeout=5)
            self.ack_thread = None

    def listen_for_acks(self):
        while not self.transfer_done.is_set():
            try:
                self.recv_sock.settimeout(1.0)   # unblocks periodically so we can check the event
                raw_bytes, _ = self.recv_sock.recvfrom(65535)
            except socket.timeout:
                continue
 
            src_ip, dst_ip, src_port, dst_port, p_type, checksum, seq, ack_num, payload = parse_packet(raw_bytes)
 
            # Filter: must be addressed to us and be an ACK packet
            if dst_port != self.server_port or p_type != TYPE_ACK:
                continue

            if self.enc_key is not None:
                try:
                    decrypt_payload(self.enc_key, self.session_id, seq, ack_num, TYPE_ACK, payload)
                except InvalidTag:
                    print(f"[SERVER] AEAD authentication failed on ACK — dropping")
                    continue
            else:
                # checksum confrimation if there is no security
                if not confirm_checksum(p_type, checksum, seq, ack_num, payload):
                    print(f"[SERVER] Checksum mismatch: corrupted ACK packet seq={seq} discarded")
                    continue
            
            # print line for debugging
            # print(f"[SERVER] ACK received: cumulative ack_num = {ack_num}")
 
            with self.window_lock:
                # duplicate ACK tracking
                if ack_num == self.last_ack_num:
                    self.dup_ack_count += 1
                else:
                    self.last_ack_num = ack_num
                    self.dup_ack_count = 0

                # remove acknowledged packets
                for seq_num in list(self.unacked.keys()):
                    if seq_num <= ack_num:
                        del self.unacked[seq_num]

                # advance window base
                if ack_num >= self.base:
                    self.base = ack_num + 1

                self.stats["received_from_client"] += 1

                # fast retransmit after 3 duplicate ACKs
                if self.dup_ack_count >= 3:
                    missing_seq = ack_num + 1
                    if missing_seq in self.unacked:
                        self.send_sock.sendto(self.unacked[missing_seq]["packet"], (self.dest_ip, 0))
                        self.unacked[missing_seq]["sent_time"] = time.time()
                        self.stats["retransmitted"] += 1
                    self.dup_ack_count = 0
 
            # If the base has moved past all packets, the entire file is acknowledged
            if self.base > self.total_packets:
                self.transfer_done.set()

    def send_file(self, filename, dest_ip, dest_port, enc_key=None, session_id=None):
        self.last_ack_num = 0
        self.dup_ack_count = 0
        self.dest_ip = dest_ip
        if not os.path.exists(filename):
            print(f"[SERVER] Error: file '{filename}' not found.")
            return
 
        # get file size to avoid loading file into memory
        file_size = os.path.getsize(filename)

        # calc hashes through streaming
        original_md5, file_digest = calc_file_hashes(filename)

        # total number of chunks
        total_packets = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        self.stats["filename"] = filename
        self.stats["filesize"] = file_size
        self.stats["start_time"] = time.time()
        self.stats["original_file_md5"] = original_md5

        self.dest_port = dest_port
        self.total_packets = total_packets
        self.enc_key    = enc_key
        self.session_id = session_id
 
        print(f"[SERVER] Sending '{filename}' | {file_size} bytes | {total_packets} packets")
 
        # Reset sliding window state
        self.base            = 1
        self.unacked         = {}

        # reset attack mode variables
        self.has_tampered = False
        self.replay_packet = None
        self.replay_seq = None
        self.replay_sent = False
        self.inject_sent = False
        self.inject_seq = None
 
        # Start ACK listener thread
        self.start_ack_thread()
 
        next_seq = 1   # next sequence number to send
        send_file_obj = open(filename, "rb")
 
        try:
            # Main loop: continue until all packets are acknowledged
            while not self.transfer_done.is_set():
                # Send new packets as long as there is space in the window and there are still packets left to send
                with self.window_lock:
                    while next_seq <= total_packets and next_seq < self.base + WINDOW_SIZE:
                        send_file_obj.seek((next_seq - 1) * CHUNK_SIZE)
                        chunk = send_file_obj.read(CHUNK_SIZE)   # seq numbers start at 1, list index at 0
                        # if enc_key is None send plaintext as before
                        if enc_key is not None:
                            chunk = encrypt_payload(enc_key, session_id, next_seq, 0, TYPE_DATA, chunk)

                        clean_packet = build_packet(
                            data=chunk,
                            seq_num=next_seq,
                            ack_num=0,
                            src_ip=self.server_ip,
                            dst_ip=dest_ip,
                            src_port=self.server_port,
                            dst_port=dest_port,
                            p_type=TYPE_DATA
                        )

                        packet = clean_packet

                        # tamper encrypted payload
                        if self.attack_mode == "tamper" and not self.has_tampered:
                            tampered_chunk = self.tamper_packet(chunk, next_seq)

                            packet = build_packet(
                                data=tampered_chunk,
                                seq_num=next_seq,
                                ack_num=0,
                                src_ip=self.server_ip,
                                dst_ip=dest_ip,
                                src_port=self.server_port,
                                dst_port=dest_port,
                                p_type=TYPE_DATA
                            )

                        # store packet if replay mode
                        if self.attack_mode == "replay" and self.replay_packet is None:
                            self.store_replay_packet(clean_packet, next_seq)

                        self.send_sock.sendto(packet, (dest_ip, 0))
    
                        # Record packet in unacked dict so we can retransmit if needed
                        self.unacked[next_seq] = {
                            "packet"    : clean_packet,
                            "sent_time" : time.time()
                        }
    
                        self.stats["packets_sent"] += 1
                        # print line for debugging
                        # print(f"[SERVER] Sent packet seq={next_seq}")
                        next_seq += 1

                # send stored replay packet if replay mode is on, packet is stored, no previoud replay packet was sent
                # send after the base seq has passed the replay seq
                if (self.attack_mode == "replay"
                    and self.replay_packet is not None
                    and not self.replay_sent
                    and self.base > self.replay_seq):
                    self.send_sock.sendto(self.replay_packet, (dest_ip, 0))
                    self.replay_sent = True
                    self.stats["packets_sent"] += 1
                    print(f"[SERVER ATTACK] Replayed old data packet seq={self.replay_seq}")

                # inject forged packet if inject mode is on and no previous injection happened.
                if self.attack_mode == "inject" and not self.inject_sent:
                    self.inject_forged_packet(dest_ip, dest_port)
    
                # Check every unacknowledged packet — if its timer has expired, resend it
                now = time.time()
                with self.window_lock:
                    if self.base in self.unacked:
                        info = self.unacked[self.base]
                        if now - info["sent_time"] > TIMEOUT:
                            self.send_sock.sendto(info["packet"], (self.dest_ip, 0))
                            self.unacked[self.base]["sent_time"] = now
                            self.stats["retransmitted"] += 1
                            # print line for debugging
                            # print(f"[SERVER] Timeout — retransmitting packet seq={seq_num}")
    
                time.sleep(0.01)
        finally:
            send_file_obj.close()
 
        # place file digest in fin payload
        fin_payload = file_digest.encode()

        # encrypt the payload if security is enabled
        if enc_key is not None:
            fin_payload = encrypt_payload(enc_key, session_id, next_seq, 0, TYPE_FIN, fin_payload)

        # Send FIN packet to indicate end of transfer
        fin_packet = build_packet(data=fin_payload, seq_num=next_seq, ack_num=0, src_ip=self.server_ip, 
                                  dst_ip=dest_ip, src_port=self.server_port, dst_port=dest_port, p_type=TYPE_FIN)
        self.send_sock.sendto(fin_packet, (dest_ip, 0))
        print("[SERVER] FIN packet sent — transfer complete.")

        # stop ack thread listener
        self.stop_ack_thread()

    def generate_output_report(self):
        # Calculate the transfer duration
        duration_seconds = int(time.time() - self.stats["start_time"])
        duration_formatted = time.strftime('%H:%M:%S', time.gmtime(duration_seconds))

        # Define the output filename
        base_name = self.stats['filename'].rsplit('.', 1)[0]
        report_name = f"server_report_{base_name}.txt"

        with open(report_name, 'w') as f:
            f.write("====================================================\n")
            f.write("SERVER REPORT\n")
            f.write("====================================================\n")
            f.write(f"Name of the transferred file: {self.stats['filename']}\n")
            f.write(f"Size of the transferred file: {self.stats['filesize']} bytes\n")
            f.write(f"The number of packets sent from the server: {self.stats['packets_sent']}\n")
            f.write(f"The number of retransmitted packets from the server: {self.stats['retransmitted']}\n")
            f.write(f"The number of packets received from the client: {self.stats['received_from_client']}\n")
            f.write(f"The time duration of the file transfer (hh:min:ss): {duration_formatted}\n")
            f.write(f"Original file MD5: {self.stats['original_file_md5']}\n")
            f.write("====================================================\n")

        print(f"Server summary report generated: {report_name}")

    def tamper_packet(self, payload_bytes, seq_num):
        """
        If attack mode set to tamper, flip 2 bits for 1 outbound data packet
        returns packet normally otherwise.
        """
        if self.attack_mode != "tamper" or self.has_tampered:
            return payload_bytes

        # avoid tampering the first packets
        if seq_num < 7:
            return payload_bytes

        tampered = bytearray(payload_bytes)

        if len(tampered) == 0:
            return payload_bytes

        # flip a bit in the encrypted payload
        tampered[0] ^= 0b00000001

        self.has_tampered = True
        print(f"[SERVER ATTACK] Tampered outbound DATA packet seq={seq_num}")

        return bytes(tampered)
    
    def store_replay_packet(self, packet, seq_num):
        """
        while in replay attack mode this will store 1 packet to be resent later.
        """
        if self.attack_mode != "replay":
            return
        if self.replay_packet is not None:
            return
        if seq_num < 7:
            return
        
        self.replay_packet = packet
        self.replay_seq = seq_num
        print(f"[SERVER ATTACK] Stored DATA packet seq={seq_num} for replay")

    def inject_forged_packet(self, dest_ip, dest_port):
        """
        inject mode function that sends 1 forged data packet.
        """
        if self.attack_mode != "inject" or self.inject_sent:
            return
        # wait for first batch of acked packets
        if self.base < 7:
            return
        
        forged_seq = self.base + 100
        forged_payload = os.urandom(32) # random payload

        forged_packet = build_packet(
            data=forged_payload,
            seq_num=forged_seq,
            ack_num=0,
            src_ip=self.server_ip,
            dst_ip=dest_ip,
            src_port=self.server_port,
            dst_port=dest_port,
            p_type=TYPE_DATA
        )

        self.send_sock.sendto(forged_packet, (dest_ip, 0))
        self.inject_sent = True
        self.inject_seq = forged_seq
        self.stats["packets_sent"] += 1
        print(f"[SERVER ATTACK] Injected forged DATA packet seq={forged_seq}")

if __name__ == "__main__":
    attack_mode = None
    # attack mode input logic, needs to have command of: sudo python3 SRFT_UDPServer.py <tamper, replay, or inject>
    # otherwise if no attack mode just use: sudo python3 SRFT_UDPServer.py
    if len(sys.argv) == 2 and (sys.argv[1] in ("tamper", "replay", "inject")):
        attack_mode = sys.argv[1]
    elif len(sys.argv) > 1:
        print("usage:")
        print("python3 SRFT_UDPServer.py")
        print("python3 SRFT_UDPServer.py tamper")
        print("python3 SRFT_UDPServer.py replay")
        print("python3 SRFT_UDPServer.py inject")
        sys.exit(1)

    server = SRFT_UDPServer()
    # set attack mode if there is one
    server.attack_mode = attack_mode

    print(f"server listening on {server.server_ip}:{server.server_port}")
    print("waiting for file request...")

    handshake_confirmed, enc_key, session_id = server.handshake()

    if (handshake_confirmed == False) :
        print("handshake connection not verified")
        sys.exit(1)

    payload_string, client_ip, client_port = server.wait_for_request()

    print("request received")
    print(f"payload: {payload_string}")
    print(f"client ip: {client_ip}")
    print(f"client port: {client_port}")

    server.send_file(payload_string, client_ip, client_port, enc_key=enc_key, session_id=session_id) # need to include derived enc_key

    server.generate_output_report()