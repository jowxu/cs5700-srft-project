import socket
import sys
from SRFT_Utils import TYPE_DATA, TYPE_ACK, TYPE_REQ, TYPE_FIN, build_packet, parse_packet, calc_file_digest_path, confirm_checksum
from Security import decrypt_payload
from cryptography.exceptions import InvalidTag

# example ips and ports
SERVER_IP = "172.31.43.77"
SERVER_PORT = 8080
CLIENT_IP = "172.31.36.216"
CLIENT_PORT = 9000

ACK_EVERY = 5

class SRFT_UDPClient:
    def __init__(self):
        # config client
        self.client_ip =  CLIENT_IP
        self.client_port = CLIENT_PORT
        #config server
        self.server_ip = SERVER_IP
        self.server_port = SERVER_PORT

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

                # decrypt package when security is enabled
                # if enc_key is provided decrypt the payload
                # if authentication fails → drop the packet and increment counter
                # if enc_key is None use payload as-is
                if enc_key is not None and p_type in (TYPE_DATA, TYPE_FIN):
                    try:
                        payload = decrypt_payload(enc_key, session_id, seq, ack, p_type, payload)
                    except InvalidTag:
                        print(f"AEAD authentication failed — dropping packet seq={seq}")
                        if p_type == TYPE_DATA:
                            received_seqs.discard(seq)
                        continue

                # only process packets addressed to this client port
                if dst_port != self.client_port:
                    continue

                # ignore unexpected packet types
                if p_type not in (TYPE_DATA, TYPE_FIN):
                    continue

                # confirm checksum for corruption
                if not confirm_checksum(p_type, checksum, seq, ack, payload):
                    print(f"corrupted packet discarded: seq={seq}")
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
                    print(f"duplicate packet discarded: seq={seq}")
                    self.send_cumulative_ack(expected_seq - 1) 
                    continue
 
                # mark this sequence number as seen
                received_seqs.add(seq)

                # store in buffer keyed by sequence number
                recv_buffer[seq] = payload
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
                
        # calculate local file digest
        local_digest = calc_file_digest_path(output_filename)
        # compare digests
        print(f"received digest: {received_digest}")
        print(f"local digest: {local_digest}")
        if local_digest == received_digest:
            print("digest match: file integrity verified")
        else:
            print("digest mismatch: file integrity compromised")

        print(f"file saved as '{output_filename}'")

    def run(self, filename, enc_key=None, session_id=None):
        """
         Full client workflow:
            1. Send file request to server
            2. Receive and reassemble the file
        """
        output_filename = f"received_{filename}"
        self.request_file(filename)
        self.receive_file(output_filename, enc_key=enc_key, session_id=session_id)


if __name__ == "__main__":
    client = SRFT_UDPClient()

    # take user input for file path
    if len(sys.argv) != 2:
        print("use correct command (replacing <filename> with the correct file path): python3 SRFT_UDPClient.py <filename>")
        sys.exit(1)
    
    filename = sys.argv[1]
    client.run(filename)