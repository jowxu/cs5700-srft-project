import socket
import os
import threading
import time
from SRFT_Utils import TYPE_DATA, TYPE_ACK, TYPE_REQ, build_packet, parse_packet

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

    def generate_output_report(self):
        # Calculate the transfer duration
        duration_seconds = int(time.time() - self.stats["start_time"])
        duration_formatted = time.strftime('%H:%M:%S', time.gmtime(duration_seconds))

        # Define the output filename
        report_name = f"transfer_report_{self.stats['filename']}.txt"

        with open(report_name, 'w') as f:
            f.write(f"Name of the transferred file: {self.stats['filename']}\n")
            f.write(f"Size of the transferred file: {self.stats['filesize']}\n")
            f.write(f"The number of packets sent from the server: {self.stats['packets_sent']}\n")
            f.write(f"The number of retransmitted packets from the server: {self.stats['retransmitted']}\n")
            f.write(f"The number of packets received from the client: {self.stats['acks_received']}\n")
            f.write(f"The time duration of the file transfer (hh:min:ss): {duration_formatted}\n")

        print(f"Summary report generated: {report_name}")

if __name__ == "__main__":
    server = SRFT_UDPServer()

    print(f"server listening on {server.server_ip}:{server.server_port}")
    print("waiting for file request")

    payload_string, client_ip, client_port = server.wait_for_request()

    print("request received")
    print(f"Payload: {payload_string}")
    print(f"client ip: {client_ip}")
    print(f"client port: {client_port}")

    server.generate_output_report()