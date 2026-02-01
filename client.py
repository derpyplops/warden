"""
Warden client: sends a UDP trigger to the server with a scenario field,
then receives the response (either UDP or TCP based on the scenario).

Supports 4 scenarios:
1. UDP normal response
2. UDP response with tampered data
3. TCP normal response
4. TCP response with tampered data

Set SCENARIO=<1-4> to control which scenario to test.
"""

import socket
import json
import hashlib
import os
import struct
from scapy.all import Ether, IP, UDP, TCP, Raw

SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"
UDP_PORT = 5000
TCP_PORT = 5000
RECV_TIMEOUT = 3  # seconds
IFACE = "veth-c"

SERVER_MAC = "02:00:0a:00:00:01"
CLIENT_MAC = "02:00:0a:00:00:02"

SCENARIO = int(os.getenv("SCENARIO", "1"))
INITIAL_SEQ_CLIENT = 2000
INITIAL_SEQ_SERVER = 1000
TCP_WINDOW = 65535


def create_raw_socket() -> socket.socket:
    """Create AF_PACKET raw socket for sending/receiving raw frames"""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((IFACE, 0))
    return sock




def build_tcp_syn() -> bytes:
    """Client initiates TCP connection with SYN"""
    pkt = Ether(dst=SERVER_MAC, src=CLIENT_MAC) / \
          IP(src=CLIENT_IP, dst=SERVER_IP, id=0, flags="DF") / \
          TCP(sport=TCP_PORT, dport=TCP_PORT,
              flags="S", seq=INITIAL_SEQ_CLIENT,
              window=TCP_WINDOW)
    return bytes(pkt)


def build_tcp_ack(server_seq: int) -> bytes:
    """Client ACKs server's SYN-ACK"""
    pkt = Ether(dst=SERVER_MAC, src=CLIENT_MAC) / \
          IP(src=CLIENT_IP, dst=SERVER_IP, id=0, flags="DF") / \
          TCP(sport=TCP_PORT, dport=TCP_PORT,
              flags="A", seq=INITIAL_SEQ_CLIENT + 1,
              ack=server_seq + 1,
              window=TCP_WINDOW)
    return bytes(pkt)


def build_tcp_fin_ack(seq: int, ack: int) -> bytes:
    """Client closes connection"""
    pkt = Ether(dst=SERVER_MAC, src=CLIENT_MAC) / \
          IP(src=CLIENT_IP, dst=SERVER_IP, id=0, flags="DF") / \
          TCP(sport=TCP_PORT, dport=TCP_PORT,
              flags="FA", seq=seq, ack=ack,
              window=TCP_WINDOW)
    return bytes(pkt)


def receive_udp_response(sock: socket.socket) -> bytes:
    """Receive UDP response frames"""
    chunks = []
    sock.settimeout(RECV_TIMEOUT)
    try:
        while True:
            frame, _ = sock.recvfrom(65535)
            chunks.append(frame)
    except socket.timeout:
        pass
    return b"".join(chunks)


def receive_tcp_response(sock: socket.socket) -> bytes:
    """Handle TCP handshake and receive data"""
    # Send SYN
    sock.send(build_tcp_syn())
    print("[client] sent TCP SYN", flush=True)

    # Wait for SYN-ACK
    syn_ack_pkt = sock.recv(65535)
    # Extract server's seq number from TCP header
    # Skip Ethernet (14) + IP header (variable, IHL*4), then TCP seq at offset 4-7
    if len(syn_ack_pkt) > 14:
        ihl = (syn_ack_pkt[14] & 0x0F) * 4
        tcp_offset = 14 + ihl
        if len(syn_ack_pkt) >= tcp_offset + 8:
            server_seq = struct.unpack("!I", syn_ack_pkt[tcp_offset + 4:tcp_offset + 8])[0]
        else:
            server_seq = 0
    else:
        server_seq = 0
    print(f"[client] received SYN-ACK with seq={server_seq}", flush=True)

    # Send ACK
    sock.send(build_tcp_ack(server_seq))
    print("[client] sent TCP ACK", flush=True)

    # Receive data frames
    chunks = []
    sock.settimeout(RECV_TIMEOUT)
    try:
        while True:
            frame = sock.recv(65535)
            # Check if it's TCP (protocol byte 23 = 6)
            if len(frame) > 42 and frame[23] == 6:
                tcp_flags = frame[47]  # TCP flags byte
                # Extract payload (skip Eth 14 + IP 20 + TCP 20 = 54)
                if len(frame) > 54:
                    chunks.append(frame[54:])
                # Check for FIN flag (0x01)
                if tcp_flags & 0x01:
                    print("[client] received FIN, closing connection", flush=True)
                    break
    except socket.timeout:
        pass

    return b"".join(chunks)


def main() -> None:
    print(f"[client] scenario {SCENARIO}", flush=True)

    trigger_data = json.dumps({"text": "hello", "scenario": SCENARIO}).encode()

    if SCENARIO in [1, 2]:
        # UDP scenarios: use standard UDP socket
        print("[client] using UDP", flush=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((CLIENT_IP, UDP_PORT))

        sock.sendto(trigger_data, (SERVER_IP, UDP_PORT))
        print("[client] trigger sent", flush=True)

        payload = receive_udp_response(sock)
        sock.close()

    elif SCENARIO in [3, 4]:
        # TCP scenarios: send trigger via UDP, then use raw socket for TCP
        print("[client] using TCP", flush=True)

        # Send trigger via normal UDP socket (won't be captured by tcpdump filter)
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind((CLIENT_IP, UDP_PORT))
        udp_sock.sendto(trigger_data, (SERVER_IP, UDP_PORT))
        print("[client] trigger sent (via UDP socket)", flush=True)
        udp_sock.close()

        # Then do TCP handshake and receive via raw socket
        raw_sock = create_raw_socket()
        payload = receive_tcp_response(raw_sock)
        raw_sock.close()

    else:
        print(f"[client] invalid scenario {SCENARIO}", flush=True)
        return

    h = hashlib.sha256(payload).hexdigest()
    print(f"[client] received {len(payload)} bytes, sha256={h}", flush=True)


if __name__ == "__main__":
    main()
