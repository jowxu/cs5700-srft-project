import socket
import sys
import secrets
import hmac
import hashlib
import time
import os
from SRFT_Config import SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT, PSK
from SRFT_Utils import TYPE_DATA, TYPE_ACK, TYPE_REQ, TYPE_FIN, build_packet, parse_packet, parse_server_hello, calc_file_digest_path, confirm_checksum
from Security import decrypt_payload
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ACK_EVERY = 5

class SRFT_UDPClient:
    def __init__(self):
        # config client
        self.client_ip =  CLIENT_IP
        self.client_port = CLIENT_PORT
        #config server
        self.server_ip = SERVER_IP
        self.server_port = SERVER_PORT

        #stats for client transfer report
        self.stats = {
            "security_enabled": "Yes",
            "handshake_status": "Fail",
            "filename": "",
            "filesize": 0,
            "packets_received": 0,
            "duplicate_packets": 0,
            "out_of_order_packets": 0,
            "checksum_errors": 0,
            "aead_auth_failures": 0,
            "received_file_md5": "",
            "sha256_match": "No",
            "start_time": 0
        }
        
        try:
            # raw send socket, headers created manually
            self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # raw recv socket, used to receive incoming UDP packets (ACKs and data)
            self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except PermissionError:
            print("root privileges required")
            exit(1)
    
    def request_file(self, filename):
        """
        Send a request packet to server where the payload is the requested filename.
        """
        # convert filename to bytes
        payload = filename.encode()

        # build packet
        packet = build_packet(data=payload, seq_num=0, ack_num=0, src_ip=self.client_ip, dst_ip=self.server_ip, 
                                   src_port=self.client_port, dst_port=self.server_port, p_type=TYPE_REQ)
        
        #print line for testing
        print(f"sending packet requesting {filename} to {self.server_ip}:{self.server_port}")

        # send packet
        self.send_sock.sendto(packet, (self.server_ip, 0))

        print("packet sent")

    def send_cumulative_ack(self, ack_num):
        """
        Sends a TYPE_ACK packet back to the server.
        """
        ack_packet = build_packet(data=b'', seq_num=0, ack_num=ack_num, src_ip=self.client_ip, dst_ip=self.server_ip, 
                                  src_port=self.client_port, dst_port=self.server_port, p_type=TYPE_ACK)
        
        self.send_sock.sendto(ack_packet, (self.server_ip, 0))
        print(f"cumulative ACK sent: ack_num = {ack_num}")
 
    def receive_file(self, output_filename, enc_key=None, session_id=None):
        """
        Receives DATA packets from the server, reassembles the file in order, and sends cumulative ACKs back.
        """
        recv_buffer = {}        # {seq_num: payload} — out of order packets
        received_seqs = set()   # duplicate detection
        expected_seq = 1        # next sequence number to write to file
        ack_counter = 0         # counts packets received since last ACK
        received_digest = ""    # reset received digest
 
        print(f"waiting to receive file, will save as '{output_filename}'")
 
        with open(output_filename, 'wb') as out_file:
            while True:
                raw_bytes, _ = self.recv_sock.recvfrom(65535)
                src_ip, dst_ip, src_port, dst_port, p_type, checksum, seq, ack, payload = parse_packet(raw_bytes)

                # only process packets addressed to this client port
                if dst_port != self.client_port:
                    continue

                # ignore unexpected packet types
                if p_type not in (TYPE_DATA, TYPE_FIN):
                    continue

                # confirm checksum for corruption
                if not confirm_checksum(p_type, checksum, seq, ack, payload):
                    self.stats["checksum_errors"] += 1
                    print(f"corrupted packet discarded: seq={seq}")
                    continue

                # decrypt package when security is enabled
                # if enc_key is provided decrypt the payload
                # if authentication fails → drop the packet and increment counter
                # if enc_key is None use payload as-is
                if enc_key is not None and p_type in (TYPE_DATA, TYPE_FIN):
                    try:
                        payload = decrypt_payload(enc_key, session_id, seq, ack, p_type, payload)
                    except InvalidTag:
                        self.stats["aead_auth_failures"] += 1
                        print(f"AEAD authentication failed — dropping packet seq={seq}")
                        if p_type == TYPE_DATA:
                            received_seqs.discard(seq)
                        continue
 
                # FIN: server is done sending — send final ACK and stop
                if p_type == TYPE_FIN:
                    print("FIN received — transfer complete")
                    received_digest = payload.decode(errors="ignore").strip()
                    self.send_cumulative_ack(expected_seq - 1)
                    break
 
                # only process DATA packets beyond this point
                if p_type != TYPE_DATA:
                    continue
 
                # Duplicate detection 
                if seq in received_seqs:
                    self.stats["duplicate_packets"] += 1
                    print(f"duplicate packet discarded: seq={seq}")
                    self.send_cumulative_ack(expected_seq - 1) 
                    continue
 
                # mark this sequence number as seen
                received_seqs.add(seq)

                # record out of order packets
                if seq != expected_seq:
                    self.stats["out_of_order_packets"] += 1

                # store in buffer keyed by sequence number
                recv_buffer[seq] = payload
                self.stats["packets_received"] += 1
                print(f"received packet seq={seq}")
 
                # write any contiguous sequence of packets starting from expected_seq
                while expected_seq in recv_buffer:
                    out_file.write(recv_buffer.pop(expected_seq))
                    print(f"written to file: seq={expected_seq}")
                    expected_seq += 1
 
                # send cumulative ACK (batched)
                ack_counter += 1
                if ack_counter >= ACK_EVERY:
                    self.send_cumulative_ack(expected_seq - 1)
                    ack_counter = 0
                
        # record file size and md5sum
        self.stats["filesize"] = os.path.getsize(output_filename)
        with open(output_filename, "rb") as f:
            self.stats["received_file_md5"] = hashlib.md5(f.read()).hexdigest()

        # calculate local file digest
        local_digest = calc_file_digest_path(output_filename)

        # compare digests
        print(f"received digest: {received_digest}")
        print(f"local digest: {local_digest}")
        if local_digest == received_digest:
            self.stats["sha256_match"] = "Yes"
            print("digest match: file integrity verified")
        else:
            self.stats["sha256_match"] = "No"
            print("digest mismatch: file integrity compromised")

        print(f"file saved as '{output_filename}'")

    def run(self, filename, enc_key=None, session_id=None):
        """
        Full client workflow:
        1. Send client hello
        2. Receive server hello & derive session key
        3. Send file request to server
        4. Receive and reassemble the file
        """
        output_filename = f"received_{filename}"
        self.stats["filename"] = filename
        self.stats["start_time"] = time.time()

        # construct client hello
        nonce_client = secrets.token_bytes(16)
        protocol_version = b"v1 " #REPLACE with actual
        client_msg = nonce_client + protocol_version
        hmac_client = hmac.digest(PSK, client_msg, hashlib.sha256)
        hello_payload = nonce_client + protocol_version + hmac_client
        hello_packet = build_packet(
            data=hello_payload,
            seq_num=0,
            ack_num=0,
            src_ip=self.client_ip,
            dst_ip=self.server_ip,
            src_port=self.client_port,
            dst_port=self.server_port,
            p_type=TYPE_REQ
        )
        # send client hello
        self.send_sock.sendto(hello_packet, (self.server_ip, 0))
        # receive server hello
        raw_bytes, _ = self.recv_sock.recvfrom(1024)
        nonce_server, server_session_id, hmac_server = parse_server_hello(raw_bytes)
        # verify server hello
        server_msg = nonce_server + server_session_id
        hmac_calc = hmac.digest(PSK, server_msg, hashlib.sha256)
        verified = hmac.compare_digest(hmac_server, hmac_calc)
        if (verified is False):
            self.generate_output_report()
            return 1
        self.stats["handshake_status"] = "Success"
        
        hkdf_input = PSK + nonce_client + nonce_server + server_session_id
        # derive session key with HKDF put in enc_key
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'')
        enc_key = hkdf.derive(hkdf_input)
        
        self.request_file(filename)
        self.receive_file(output_filename, enc_key=enc_key, session_id=server_session_id)
        self.generate_output_report()
        return 0
    
    def generate_output_report(self):
        # Calculate the transfer duration
        duration_seconds = int(time.time() - self.stats["start_time"])
        duration_formatted = time.strftime('%H:%M:%S', time.gmtime(duration_seconds))

        # Define the output filename
        base_name = self.stats['filename'].rsplit('.', 1)[0]
        report_name = f"client_report_{base_name}.txt"

        with open(report_name, 'w') as f:
            f.write("====================================================\n")
            f.write("CLIENT REPORT\n")
            f.write("====================================================\n")
            f.write(f"Security enabled (PSK + AEAD): {self.stats['security_enabled']}\n")
            f.write(f"Handshake status: {self.stats['handshake_status']}\n")
            f.write(f"Size of the transferred file: {self.stats['filesize']} bytes\n")
            f.write(f"Number of packets received from the server: {self.stats['packets_received']}\n")
            f.write(f"Number of duplicate packets: {self.stats['duplicate_packets']}\n")
            f.write(f"Number of out-of-order packets: {self.stats['out_of_order_packets']}\n")
            f.write(f"Number of packets with checksum errors: {self.stats['checksum_errors']}\n")
            f.write(f"Time duration of the file transfer: {duration_formatted}\n")
            f.write(f"Received file MD5: {self.stats['received_file_md5']}\n")
            f.write(f"AEAD authentication failures: {self.stats['aead_auth_failures']}\n")
            f.write(f"SHA-256 match: {self.stats['sha256_match']}\n")
            f.write("====================================================\n")
        
        print(f"Client summary report generated: {report_name}")


if __name__ == "__main__":
    client = SRFT_UDPClient()

    # take user input for file path
    if len(sys.argv) != 2:
        print("use correct command (replacing <filename> with the correct file path): python3 SRFT_UDPClient.py <filename>")
        sys.exit(1)
    
    filename = sys.argv[1]
    result = client.run(filename)
    if (result == 1) :
        print("handshake connection not verified")
        sys.exit(1)