"""
Warden client: sends a UDP trigger to the server with a scenario field,
then receives the response (either UDP or TCP based on the scenario).

Supports 5 scenarios:
1. UDP normal response
2. UDP response with tampered data
3. TCP normal response
4. TCP response with tampered data
5. TCP response with steganographic data in IP padding
"""

import socket
import json
import hashlib
import os
import struct
import time
from scapy.all import Ether, IP, UDP, TCP, Raw

SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"
UDP_PORT = 5000
TCP_SERVER_PORT = 5000
TCP_CLIENT_PORT = 5001
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
          TCP(sport=TCP_CLIENT_PORT, dport=TCP_SERVER_PORT,
              flags="S", seq=INITIAL_SEQ_CLIENT,
              window=TCP_WINDOW)
    return bytes(pkt)


def build_tcp_ack(server_seq: int) -> bytes:
    """Client ACKs server's SYN-ACK"""
    pkt = Ether(dst=SERVER_MAC, src=CLIENT_MAC) / \
          IP(src=CLIENT_IP, dst=SERVER_IP, id=0, flags="DF") / \
          TCP(sport=TCP_CLIENT_PORT, dport=TCP_SERVER_PORT,
              flags="A", seq=INITIAL_SEQ_CLIENT + 1,
              ack=server_seq + 1,
              window=TCP_WINDOW)
    return bytes(pkt)


def build_tcp_fin_ack(seq: int, ack: int) -> bytes:
    """Client closes connection"""
    pkt = Ether(dst=SERVER_MAC, src=CLIENT_MAC) / \
          IP(src=CLIENT_IP, dst=SERVER_IP, id=0, flags="DF") / \
          TCP(sport=TCP_CLIENT_PORT, dport=TCP_SERVER_PORT,
              flags="FA", seq=seq, ack=ack,
              window=TCP_WINDOW)
    return bytes(pkt)


def receive_udp_response(sock: socket.socket) -> bytes:
    """Receive UDP response frames"""
    chunks = []
    sock.settimeout(RECV_TIMEOUT)
    try:
        while True:
            data, _ = sock.recvfrom(65535)
            chunks.append(data)
    except socket.timeout:
        pass
    return b"".join(chunks)


def receive_udp_with_timing_decoding(sock: socket.socket) -> bytes:
    """Receive UDP response and decode Chupja timing channel"""
    chunks = []
    
    # Timing analysis
    arrival_times = []
    
    sock.settimeout(RECV_TIMEOUT)
    try:
        while True:
            data, _ = sock.recvfrom(65535)
            # High-precision timestamp
            arrival_times.append(time.perf_counter())
            chunks.append(data)
    except socket.timeout:
        pass
        
    # Decode Chupja
    # Threshold between 200us ('0') and 500us ('1') = 350us = 0.00035s
    # Skip first 5 packets (priming)
    if len(arrival_times) > 5:
        deltas = []
        bits = ""
        # Calculate IPDs
        for i in range(5, len(arrival_times)):
            diff = arrival_times[i] - arrival_times[i-1]
            deltas.append(diff)
            if diff > 0.00035: # 350us
                bits += "1"
            else:
                bits += "0"
        
        # Group into bytes
        decoded_bytes = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte_str = bits[i:i+8]
                try:
                    decoded_bytes.append(int(byte_str, 2))
                except ValueError:
                    pass
        
        try:
            secret = decoded_bytes.decode('utf-8', errors='ignore')
            print(f"[client] covert analysis: FOUND PATTERN", flush=True)
            print(f"COVERT_DATA_JSON: {json.dumps({'bits': bits, 'secret': secret})}", flush=True)
            print(f"[client] decoded secret: '{secret}'", flush=True)
        except Exception:
            print("[client] covert analysis: garbage data", flush=True)
            
    return b"".join(chunks)


def receive_tcp_response(raw_sock: socket.socket) -> bytes:
    """Handle TCP handshake and receive data"""
    # Send SYN
    raw_sock.send(build_tcp_syn())
    print("[client] sent TCP SYN", flush=True)

    # Wait for SYN-ACK
    raw_sock.settimeout(RECV_TIMEOUT)
    server_seq = None
    max_attempts = 20

    for attempt in range(max_attempts):
        try:
            frame = raw_sock.recv(65535)
            pkt = Ether(frame)

            # Validate packet structure
            if IP not in pkt or TCP not in pkt:
                continue

            ip_pkt = pkt[IP]
            tcp_pkt = pkt[TCP]

            # Check source/dest match
            if ip_pkt.src != SERVER_IP or ip_pkt.dst != CLIENT_IP:
                continue

            if tcp_pkt.sport != TCP_SERVER_PORT or tcp_pkt.dport != TCP_CLIENT_PORT:
                continue

            # Check for SYN-ACK flags
            if not (tcp_pkt.flags & 0x02):  # SYN flag required
                continue
            if not (tcp_pkt.flags & 0x10):  # ACK flag required
                continue

            server_seq = tcp_pkt.seq
            print(f"[client] received SYN-ACK with seq={server_seq}", flush=True)
            break

        except Exception:
            continue

    if server_seq is None:
        print("[client] timeout waiting for SYN-ACK", flush=True)
        return b""

    # Send ACK
    raw_sock.send(build_tcp_ack(server_seq))
    print("[client] sent TCP ACK", flush=True)

    # Receive data frames
    chunks = []
    client_ack = INITIAL_SEQ_CLIENT + 1

    try:
        while True:
            frame = raw_sock.recv(65535)
            pkt = Ether(frame)

            # Validate packet structure
            if IP not in pkt or TCP not in pkt:
                continue

            ip_pkt = pkt[IP]
            tcp_pkt = pkt[TCP]

            # Check source/dest match
            if ip_pkt.src != SERVER_IP or ip_pkt.dst != CLIENT_IP:
                continue

            if tcp_pkt.sport != TCP_SERVER_PORT or tcp_pkt.dport != TCP_CLIENT_PORT:
                continue

            # Extract payload if present
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                chunks.append(payload)
                client_ack = tcp_pkt.seq + len(payload)

            # Check for FIN flag
            if tcp_pkt.flags & 0x01:  # FIN flag
                print("[client] received FIN, closing connection", flush=True)
                break

    except socket.timeout:
        pass

    return b"".join(chunks)


def main() -> None:
    print(f"[client] scenario {SCENARIO}", flush=True)

    trigger_data = json.dumps({"text": "hello", "scenario": SCENARIO}).encode()

    trigger_data = json.dumps({"text": "hello", "scenario": SCENARIO}).encode()
    
    if SCENARIO == 6:
        # UDP with timing analysis
        print("[client] using UDP with Timing Analysis", flush=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((CLIENT_IP, UDP_PORT))

        sock.sendto(trigger_data, (SERVER_IP, UDP_PORT))
        print("[client] trigger sent", flush=True)

        payload = receive_udp_with_timing_decoding(sock)
        sock.close()

    elif SCENARIO in [1, 2]:
        # UDP scenarios: use standard UDP socket
        print("[client] using UDP", flush=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((CLIENT_IP, UDP_PORT))

        sock.sendto(trigger_data, (SERVER_IP, UDP_PORT))
        print("[client] trigger sent", flush=True)

        payload = receive_udp_response(sock)
        sock.close()

    elif SCENARIO in [3, 4, 5]:
        # TCP scenarios: send trigger via UDP, then use raw socket for TCP
        print("[client] using TCP", flush=True)

        # Send trigger via normal UDP socket
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind((CLIENT_IP, UDP_PORT))
        udp_sock.sendto(trigger_data, (SERVER_IP, UDP_PORT))
        print("[client] trigger sent (via UDP socket)", flush=True)
        udp_sock.close()

        # Small delay to let server process trigger
        time.sleep(0.05)

        # Then do TCP handshake and receive via raw socket
        raw_sock = create_raw_socket()
        payload = receive_tcp_response(raw_sock)
        raw_sock.close()

    else:
        print(f"[client] invalid scenario {SCENARIO}", flush=True)
        return

    h = hashlib.sha256(payload).hexdigest()
    print(f"[client] received {len(payload)} bytes, sha256={h}", flush=True)

    # Output JSON line for run.sh to capture
    import json as json_module
    result = {
        "payload_size": len(payload),
        "payload_sha256": h
    }
    print(f"PAYLOAD_HASH_JSON: {json_module.dumps(result)}", flush=True)


if __name__ == "__main__":
    main()
