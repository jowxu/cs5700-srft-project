# CS5700 - Secure Reliable File Transfer

## Group 13

**Members**
- Claire Stanton
- Viraj Sheth
- Joel Xu
- Zhiye Li

## File Structure

| File | Description |
|---|---|
| `SRFT_UDPServer.py` | Server program — handles handshake, file sending, sliding window, and report generation |
| `SRFT_UDPClient.py` | Client program — handles handshake, file request, and file reassembly |
| `SRFT_Utils.py` | Shared utilities — packet builder, parsers, checksum, and digest functions |
| `Security.py` | Encryption, decryption and AAD construction |
| `SRFT_Config.py` | Configuration file — server/client IPs, ports, and PSK |

## Setup

### File Deployment

**On the server EC2 instance**, copy the following files:
- `SRFT_UDPServer.py`
- `SRFT_Utils.py`
- `SRFT_Config.py`
- `Security.py`
- The files you want to transfer

**On the client EC2 instance**, copy the following files:
- `SRFT_UDPClient.py`
- `SRFT_Utils.py`
- `SRFT_Config.py`
- `Security.py`

### How to Run

SSH into both instances with separate console instances.

**Step 1 — Start the server first:**
```bash
sudo python3 SRFT_UDPServer.py
sudo python3 SRFT_UDPServer.py <tamper/replay/inject>
```
 Do not add additional argument if the server is to be ran in normal mode.
 
 To turn on attack mode, replace `<tamper/replay/inject>` with `tamper`, `replay`, or `inject` to turn on the respective attack mode.

**Step 2 — Start the client, providing the filename to request:**
```bash
sudo python3 SRFT_UDPClient.py <filepath>
```
Replace `<filepath>` with the name or path of the file to be transferred.
 
The server must be running and waiting before the client is started.

## How the Application Works

### Phase 1 — Reliable Transfer

**Checksum:** A ones-complement checksum is calculated over the SRFT header and payload when building each packet, and verified upon receipt. Corrupted packets are silently discarded.
 
**Sequence Numbers:** Every data packet is assigned an increasing sequence number starting from 1. The receiver uses sequence numbers to detect duplicates, handle out-of-order delivery, and reassemble the file in the correct order.
 
**Cumulative Acknowledgements:** The client sends a single cumulative ACK every 5 received packets (rather than one ACK per packet), acknowledging all packets up to and including the highest continuous sequence number received.
 
**Sliding Window with Timeout Retransmission:** The server maintains a sliding window of size 16. Every sent packet is stored in an unacked dictionary with its send timestamp. A background ACK listener thread continuously removes acknowledged packets from the window. A separate timeout check re-sends any packet whose timer has exceeded 2 seconds without acknowledgement.

**Multithreading:** To allow sending and ACK reception to happen simultaneously, the server uses Python's threading module. A dedicated background thread (`listen_for_acks`) runs continuously during file transfer, parsing incoming packets, filtering for `TYPE_ACK`, and updating the shared window state. The main thread handles sending new packets and checking for timeouts.
 
**File Integrity:** After transfer, the received file can be verified against the original using `md5sum` on both machines

### Phase 2 — Secure and Reliable File Transfer

**Security Handshake (Session Establishment):**
 
Before any file data is exchanged, the client and server perform a two-message handshake:
 
1. **ClientHello** — The client generates a 16-byte random `nonce_client` and a 3-byte protocol version string. It computes `HMAC-SHA256(PSK, nonce_client + protocol_version)` and sends all three fields as the packet payload.
2. **ServerHello** — The server verifies the client HMAC. If verification passes, it generates a 16-byte `nonce_server` and an 8-byte `session_id`, computes, and replies with all three fields.
If either HMAC fails verification, the connection is rejected immediately and no file data is transferred.

**Session Key Derivation (HKDF):**
 
After a successful handshake, both sides independently derive a 32-byte `enc_key` using HKDF-SHA256. This key is unique per session and never transmitted over the network.

**AES-GCM Authenticated Encryption (AEAD):**
 
All DATA, FIN, and ACK packets are protected using AES-GCM. For each packet:
- A 12-byte nonce is derived from the sequence number and prepended to the ciphertext.
- Additional Authenticated Data (AAD) is constructed by binding `session_id`, `seq_num`, `ack_num`, and `p_type` together. This means any tampering with packet control fields will cause authentication to fail even without touching the ciphertext.
- AES-GCM's 16-byte authentication tag is automatically appended by the `cryptography` library.

**End-to-End SHA-256 Verification:**
 
Before sending, the server computes `SHA-256(file_bytes)` and sends the hex digest inside the FIN packet, protected by AEAD. After the client reconstructs the file, it computes the same digest locally and compares. The transfer is only reported as successful if the digests match.

## Limitations

## Lessons Learned


- Building IP and UDP headers manually from scratch gave us a deep understanding of how the protocol stack actually works beneath socket abstractions.

- Implementing sequence numbers, cumulative ACKs, retransmission, and sliding window together taught us that reliable data transfer involves many interacting mechanisms, and getting one wrong breaks all the others.


## Possible Future Improvements

- Support transferring multiple files per session without restarting the handshake.

- Add certificate-based authentication as an alternative to PSK for stronger identity guarantees.

- Add congestion control and selective ACK algorithms to create a more robust retransmission system.

- To implement Replay Protection, we will implement a sliding-window replay protection on the client side, replacing the simple duplicate-detection set and independent expected sequence number. It will distinguish duplicates, out-of-window attack packets, and legitimate new packets by rejecting sequence numbers beyond max_delivered + window_size (128), preventing sequence number jump attacks and unbounded memory usage. The core logic will encapsulate duplicate detection, window boundary, max_delivered, and buffered set into a single object: check() will determine packet status, mark_received() will buffer valid packets, and advance() will automatically move the window forward when contiguous sequence numbers are received. Cumulative ACKs will always be sent as expected_seq() - 1, ensuring they reflect true in-order delivery progress. The design will strictly follow the authenticate‑then‑replay order: AEAD decryption will happen before replay checking, so forged packets cannot pollute the window state.

## References
1. https://docs.python.org/3/library/hmac.html
2. socket — Low-level networking interfacePython documentationhttps://docs.python.org › library › socket
3. https://docs.python.org/3/library/socket.html
4. https://docs.python.org/3/library/struct.html
5. https://docs.python.org/3/library/hashlib.html
6. https://cryptography.io/en/latest/hazmat/primitives/aead
7. https://crypto.stackexchange.com/questions/102590/encrypt-multiple-chunks-of-data-with-an-aead
