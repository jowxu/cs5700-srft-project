import socket
import struct

# types for header
TYPE_DATA = 0
TYPE_ACK = 1
TYPE_REQ = 2

# example ips and ports
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
CLIENT_IP = "127.0.0.1"
CLIENT_PORT = 9000

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
        except PermissionError:
            print("root privileges required")
            exit(1)

    def build_packet(self, data, seq_num, ack_num, src_ip, dst_ip, src_port, dst_port, p_type=0):
        """
        Constructs full packet from scratch
        Structure: [IP Header] + [UDP Header] + [SRFT Header] + [File Data]
        """

        # 1: SRFT PROTOCOL HEADER
        # Format explanation for struct.pack('!B H I I'):
        # ! = Network byte order (Big-endian)
        # B = Type (1 byte: 0 for Data, 1 for ACK)
        # H = Checksum (2 bytes: initially set to 0)
        # I = Sequence Number (4 bytes)
        # I = Acknowledgement Number (4 bytes)

        # NOTE FOR TEAM: Replace the '0' with the actual checksum function

        srft_header = struct.pack('!B H I I', p_type, 0, seq_num, ack_num)

        # 2: UDP HEADER
        # Fields: Source Port, Dest Port, Total Length (Header + Data), Checksum
        # Total length = 8 bytes (UDP) + 11 bytes (SRFT) + actual data length
        udp_len = 8 + len(srft_header) + len(data)
        udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)

        # 3: IP HEADER
        # Standard IPv4 header construction
        # Includes Version, IHL, Total Length, ID, TTL, Protocol (17 for UDP)
        # NOTE: Src/Dst IP addresses should be updated for AWS testing
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                69, 0, 20 + udp_len, 54321, 0, 64, 17, 0,
                                socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

        # Combine all parts into one raw byte stream
        return ip_header + udp_header + srft_header + data
    
    def request_file(self, filename):
        """
        Send a request packet to server where the payload is the requested filename.
        """
        # convert filename to bytes
        payload = filename.encode()

        # build packet
        packet = self.build_packet(data=payload, seq_num=0, ack_num=0, src_ip=self.client_ip, dst_ip=self.server_ip, 
                                   src_port=self.client_port, dst_port=self.server_port, p_type=TYPE_REQ)
        
        #print line for testing
        print(f"sending packet requesting {filename} to {self.server_ip}:{self.server_port}")

        # send packet
        self.send_sock.sendto(packet, (self.server_ip, 0))

        print("packet sent")

if __name__ == "__main__":
    client = SRFT_UDPClient()

    filename = "test1.txt"
    client.request_file(filename)