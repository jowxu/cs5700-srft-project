import socket
import struct
import os
import threading
import time

# global variables
TYPE_DATA = 0
TYPE_ACK  = 1
TYPE_REQ  = 2 # type for client requests file

class SRFT_UDPServer:
    def __init__(self):
        self.stats = {
            "filename": "",
            "filesize": 0,
            "packets_sent": 0,
            "retransmitted": 0,
            "acks_received": 0,
            "start_time": 0
        }

        # config server port and ip
        self.server_port = 8080
        self.server_ip = "127.0.0.1" # loopback ip, can change to other viable ip's

        try:
            # Using IPPROTO_RAW to manually build IP headers
            self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            # receiver socket (used to receive incoming UDP packets)
            self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except PermissionError:
            print("Error: Root privileges required.")
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
    
    def parse_packet(self, raw_bytes):
        """
        packet parser (currently is minimal)
        returns: src_ip, dst_ip, src_port, dst_port, p_type, checksum, seq, ack, payload
        """
        # ip header (minimum 20 bytes)
        ihl = (raw_bytes[0] & 0x0F) * 4 # convert 32 word bits to bytes
        src_ip = socket.inet_ntoa(raw_bytes[12:16]) # bytes 12-15: source ip address
        dst_ip = socket.inet_ntoa(raw_bytes[16:20]) # bytes 16-19: destination ip address

        # get udp header
        udp_start = ihl
        udp_header = raw_bytes[udp_start:udp_start + 8]
        src_port, dst_port, udp_len, udp_checksum = struct.unpack('!HHHH', udp_header)

        # get srft header
        srft_start = udp_start + 8
        srft_header = raw_bytes[srft_start:srft_start + 11]  # 1 + 2 + 4 + 4 = 11 bytes
        p_type, checksum, seq, ack = struct.unpack('!B H I I', srft_header)

        #get payload
        payload = raw_bytes[srft_start + 11: udp_start + udp_len]  # udp length includes the header

        return src_ip, dst_ip, src_port, dst_port, p_type, checksum, seq, ack, payload
    
    def wait_for_request(self):
        """
        wait for a client request packet. (Currently payload will just be filename).
        return: filename, src_ip, src_port
        """
        while True:
            # wait for packet
            raw_bytes, address = self.recv_sock.recvfrom(65535) #returns tuple, address redundant so ignore it

            # parse packet and fill in variables
            src_ip, dst_ip, src_port, dst_port, p_type, checksum, seq, ack, payload = self.parse_packet(raw_bytes)

            # If port and server port dont match, ignore packet
            if dst_port != self.server_port:
                continue

            # check type, make sure it is a request type packet
            if p_type == TYPE_REQ:
                #convert payload from bytes to string
                payload_string = payload.decode(errors="ignore").strip()

                print(f"received file request: '{payload_string}' from {src_ip}:{src_port}")

                return payload_string, src_ip, src_port

    def listen_for_acks(self):
        # TODO: Implement background thread to receive and parse ACKs
        # RECV
        pass

    def send_file(self, filename, dest_ip):
        # TODO: Implement segmentation and timeout retransmission
        # RETRANSMISSION TIMER
        pass

if __name__ == "__main__":
    server = SRFT_UDPServer()

    print(f"server listening on {server.server_ip}:{server.server_port}")
    print("waiting for file request")

    payload_string, client_ip, client_port = server.wait_for_request()

    print("request received")
    print(f"Payload: {payload_string}")
    print(f"client ip: {client_ip}")
    print(f"client port: {client_port}")