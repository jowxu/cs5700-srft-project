import socket
from SRFT_Utils import TYPE_DATA, TYPE_ACK, TYPE_REQ, TYPE_FIN, build_packet, parse_packet
from SRFT_Replay import ReplayWindow

# example ips and ports
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
CLIENT_IP = "127.0.0.1"
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
 
    def receive_file(self, output_filename):
        """
        Receives DATA packets from the server, reassembles the file in order, and sends cumulative ACKs back.
        """
        recv_buffer = {}
        replay = ReplayWindow(window_size=128)
        ack_counter = 0
        replay_drops = 0
 
        print(f"waiting to receive file, will save as '{output_filename}'")
 
        with open(output_filename, 'wb') as out_file:
            while True:
                raw_bytes, _ = self.recv_sock.recvfrom(65535)
                src_ip, dst_ip, src_port, dst_port, p_type, checksum, seq, ack, payload = parse_packet(raw_bytes)
 
                # only process packets addressed to this client port
                if dst_port != self.client_port:
                    continue
 
                # FIN: server is done sending — send final ACK and stop
                if p_type == TYPE_FIN:
                    print("FIN received — transfer complete")
                    self.send_cumulative_ack(replay.expected_seq() - 1)
                    break
 
                # only process DATA packets beyond this point
                if p_type != TYPE_DATA:
                    continue

                status = replay.check(seq)

                if status == "duplicate":
                    replay_drops += 1
                    print(f"duplicate packet discarded: seq={seq}")
                    continue

                if status == "out_of_window":
                    replay_drops += 1
                    print(f"out-of-window packet discarded: seq={seq}")
                    continue

                replay.mark_received(seq)
                recv_buffer[seq] = payload
                print(f"received packet seq={seq}")

                while replay.expected_seq() in recv_buffer:
                    next_seq = replay.expected_seq()
                    out_file.write(recv_buffer.pop(next_seq))
                    print(f"written to file: seq={next_seq}")
                    replay.advance()
 
                # send cumulative ACK (batched)
                ack_counter += 1
                if ack_counter >= ACK_EVERY:
                    self.send_cumulative_ack(replay.expected_seq() - 1)
                    ack_counter = 0
                elif len(recv_buffer) == 0:
                    self.send_cumulative_ack(replay.expected_seq() - 1)
                    ack_counter = 0
 
        print(f"file saved as '{output_filename}'")

    def run(self, filename):
        """
         Full client workflow:
            1. Send file request to server
            2. Receive and reassemble the file
        """
        output_filename = f"received_{filename}"
        self.request_file(filename)
        self.receive_file(output_filename)


if __name__ == "__main__":
    client = SRFT_UDPClient()

    filename = "test1.txt"
    client.run(filename)