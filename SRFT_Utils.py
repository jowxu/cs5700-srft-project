import socket
import struct
import hashlib

# packet types
TYPE_DATA = 0
TYPE_ACK = 1
TYPE_REQ = 2  # packet type used when the client requests a file
TYPE_FIN = 3  # packet type used to indicate the end of a file transfer


def build_packet(data, seq_num, ack_num, src_ip, dst_ip, src_port, dst_port, p_type=0):
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
    temp_udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    checksum = udp_checksum_calc(temp_udp_header, data)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, checksum)

    # 3: IP HEADER
    # Standard IPv4 header construction
    # Includes Version, IHL, Total Length, ID, TTL, Protocol (17 for UDP)
    # NOTE: Src/Dst IP addresses should be updated for AWS testing
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            69, 0, 20 + udp_len, 54321, 0, 64, 17, 0,
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

    # Combine all parts into one raw byte stream
    return ip_header + udp_header + srft_header + data


def parse_packet(raw_bytes):
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

def udp_checksum_calc(udp_header, data): #udp_header is the header object with 0 in place of checksum
        packet = udp_header + data

        # if len is odd
        if len(packet) % 2 != 0:
            packet += b'\x00'
        # calculate one's complement sum
        sum = 0
        for i in range(0, len(packet), 2):
            w = (packet[i] << 8) + packet[i+1]
            temp = sum + w
            sum = (temp & 0xffff) + (temp >> 16)
    
        checksum_val = ~sum & 0xffff
        return checksum_val

def calc_file_digest_bytes(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

def calc_file_digest_path(file_path):
    file_bytes = open(file_bytes, "rb").read()
    return calc_file_digest_bytes(file_bytes)

def verify_file_digest(file_path, expected_digest):
    actual_digest = calc_file_digest_path(file_path)
    return actual_digest == expected_digest