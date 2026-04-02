import socket
import os
import threading
import time
from SRFT_Utils import TYPE_DATA, TYPE_ACK, TYPE_REQ, TYPE_FIN, build_packet, parse_packet

# Sliding window specifications
WINDOW_SIZE  = 16 
TIMEOUT = 2.0
CHUNK_SIZE = 1024  # size of each file chunk to send (in bytes)

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
        self.server_ip = "172.31.43.77" # loopback ip, can change to other viable ip's

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
 
            print(f"[SERVER] ACK received: cumulative ack_num = {ack_num}")
 
            with self.window_lock:
                # Remove every packet whose seq_num <= ack_num from the unacked dict.
                # These are now safely delivered — no need to retransmit them.
                for seq_num in list(self.unacked.keys()):
                    if seq_num <= ack_num:
                        del self.unacked[seq_num]
 
                # Advance the window base
                if ack_num >= self.base:
                    self.base = ack_num + 1
 
                self.stats["acks_received"] += 1
 
            # If the base has moved past all packets, the entire file is acknowledged
            if self.base > self.total_packets:
                self.transfer_done.set()

    def send_file(self, filename, dest_ip, dest_port):
        if not os.path.exists(filename):
            print(f"[SERVER] Error: file '{filename}' not found.")
            return
 
        with open(filename, 'rb') as f:
            file_data = f.read()
 
        chunks        = [file_data[i: i + CHUNK_SIZE] for i in range(0, len(file_data), CHUNK_SIZE)]
        total_packets = len(chunks)
 
        self.stats["filename"]   = filename
        self.stats["filesize"]   = len(file_data)
        self.stats["start_time"] = time.time()

        self.dest_port = dest_port
        self.total_packets = total_packets
 
        print(f"[SERVER] Sending '{filename}' | {len(file_data)} bytes | {total_packets} packets")
 
        # Reset sliding window state
        self.base            = 1
        self.unacked         = {}
 
        # Start ACK listener thread
        self.start_ack_thread()
 
        next_seq = 1   # next sequence number to send
 
        # Main loop: continue until all packets are acknowledged
        while not self.transfer_done.is_set():
            # Send new packets as long as there is space in the window and there are still packets left to send
            with self.window_lock:
                while next_seq <= total_packets and next_seq < self.base + WINDOW_SIZE:
                    chunk  = chunks[next_seq - 1]   # seq numbers start at 1, list index at 0
                    packet = build_packet(data=chunk, seq_num=next_seq, ack_num=0, src_ip=self.server_ip,
                                           dst_ip=dest_ip, src_port=self.server_port, dst_port=dest_port, p_type=TYPE_DATA) 
                    self.send_sock.sendto(packet, (dest_ip, 0))
 
                    # Record packet in unacked dict so we can retransmit if needed
                    self.unacked[next_seq] = {
                        "packet"    : packet,
                        "sent_time" : time.time()
                    }
 
                    self.stats["packets_sent"] += 1
                    print(f"[SERVER] Sent packet seq={next_seq}")
                    next_seq += 1
 
            # Check every unacknowledged packet — if its timer has expired, resend it
            now = time.time()
            with self.window_lock:
                for seq_num, info in list(self.unacked.items()):
                    if now - info["sent_time"] > TIMEOUT:
                        self.send_sock.sendto(info["packet"], (dest_ip, 0))
                        self.unacked[seq_num]["sent_time"] = now   # reset the timer
                        self.stats["retransmitted"] += 1
                        print(f"[SERVER] Timeout — retransmitting packet seq={seq_num}")
 
            time.sleep(0.01)
 
        # Send FIN packet to indicate end of transfer
        fin_packet = build_packet(data=b'', seq_num=next_seq, ack_num=0, src_ip=self.server_ip, 
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
        report_name = f"transfer_report_{base_name}.txt"

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

    server.send_file(payload_string, client_ip, client_port)

    server.generate_output_report()