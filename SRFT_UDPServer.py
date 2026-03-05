import socket
import struct
import os
import threading
import time


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

        try:
            # Using IPPROTO_RAW to manually build IP headers
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except PermissionError:
            print("Error: Root privileges required.")
            exit(1)

    def build_packet(self, data, seq_num, ack_num, p_type=0):
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
        udp_header = struct.pack('!HHHH', 8080, 8080, udp_len, 0)

        # 3: IP HEADER
        # Standard IPv4 header construction
        # Includes Version, IHL, Total Length, ID, TTL, Protocol (17 for UDP)
        # NOTE: Src/Dst IP addresses should be updated for AWS testing
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                69, 0, 20 + udp_len, 54321, 0, 64, 17, 0,
                                socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))

        # Combine all parts into one raw byte stream
        return ip_header + udp_header + srft_header + data

    def listen_for_acks(self):
        # TODO: Implement background thread to receive and parse ACKs
        # RECV
        pass

    def send_file(self, filename, dest_ip):
        # TODO: Implement segmentation and timeout retransmission
        # RETRANSMISSION TIMER
        pass