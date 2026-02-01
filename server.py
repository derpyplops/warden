"""
Warden server: precomputes deterministic Ethernet frames from a JSON payload,
listens for a UDP trigger on an AF_PACKET raw socket, then sends the
precomputed frames in order based on the scenario specified in the trigger.

Supports 4 scenarios:
1. UDP normal response
2. UDP response with tampered data
3. TCP normal response
4. TCP response with tampered data
"""

import struct
import socket
import json
import sys
import argparse
from scapy.all import Ether, IP, UDP, TCP, Raw

# --- Configuration ---
IFACE = "veth-s"
SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"
SERVER_MAC = "02:00:0a:00:00:01"
CLIENT_MAC = "02:00:0a:00:00:02"
SRC_PORT = 5000
DST_PORT = 5000
TCP_PORT = 5000
UDP_PORT = 5000
MAX_PAYLOAD_UDP = 1472  # 1500 MTU - 20 (IP) - 8 (UDP)
MAX_PAYLOAD_TCP = 1432  # 1500 MTU - 20 (IP) - 20 (TCP) - extra overhead
INITIAL_SEQ_SERVER = 1000
INITIAL_SEQ_CLIENT = 2000
TCP_WINDOW = 65535


def build_udp_frame(ip_id: int, chunk: bytes) -> bytes:
    """Build UDP frame using Scapy"""
    pkt = Ether(dst=CLIENT_MAC, src=SERVER_MAC) / \
          IP(src=SERVER_IP, dst=CLIENT_IP, id=ip_id, flags="DF") / \
          UDP(sport=SRC_PORT, dport=DST_PORT, chksum=0) / \
          Raw(load=chunk)
    return bytes(pkt)


def build_tcp_syn_ack() -> bytes:
    """Server responds with SYN-ACK to client's SYN"""
    pkt = Ether(dst=CLIENT_MAC, src=SERVER_MAC) / \
          IP(src=SERVER_IP, dst=CLIENT_IP, id=0, flags="DF") / \
          TCP(sport=TCP_PORT, dport=TCP_PORT,
              flags="SA", seq=INITIAL_SEQ_SERVER,
              ack=INITIAL_SEQ_CLIENT + 1,
              window=TCP_WINDOW)
    return bytes(pkt)


def build_tcp_data_frame(ip_id: int, seq: int, chunk: bytes) -> bytes:
    """Build TCP data frame with PSH+ACK flags"""
    pkt = Ether(dst=CLIENT_MAC, src=SERVER_MAC) / \
          IP(src=SERVER_IP, dst=CLIENT_IP, id=ip_id, flags="DF") / \
          TCP(sport=TCP_PORT, dport=TCP_PORT,
              flags="PA", seq=seq,
              ack=INITIAL_SEQ_CLIENT + 1,
              window=TCP_WINDOW) / \
          Raw(load=chunk)
    return bytes(pkt)


def build_tcp_fin_ack(seq: int, ack: int) -> bytes:
    """Server closes connection with FIN+ACK"""
    pkt = Ether(dst=CLIENT_MAC, src=SERVER_MAC) / \
          IP(src=SERVER_IP, dst=CLIENT_IP, id=0, flags="DF") / \
          TCP(sport=TCP_PORT, dport=TCP_PORT,
              flags="FA", seq=seq, ack=ack,
              window=TCP_WINDOW)
    return bytes(pkt)


def precompute_udp_frames(payload: bytes) -> list[bytes]:
    """Precompute UDP data frames from payload"""
    frames = []
    offset = 0
    ip_id = 0
    while offset < len(payload):
        chunk = payload[offset : offset + MAX_PAYLOAD_UDP]
        frames.append(build_udp_frame(ip_id, chunk))
        offset += MAX_PAYLOAD_UDP
        ip_id += 1
    return frames


def precompute_tcp_frames(payload: bytes) -> list[bytes]:
    """Precompute TCP data frames from payload"""
    frames = []
    offset = 0
    ip_id = 1
    seq = INITIAL_SEQ_SERVER + 1  # After SYN-ACK

    while offset < len(payload):
        chunk = payload[offset : offset + MAX_PAYLOAD_TCP]
        frames.append(build_tcp_data_frame(ip_id, seq, chunk))
        offset += MAX_PAYLOAD_TCP
        seq += len(chunk)
        ip_id += 1

    return frames


def parse_trigger_json(pkt: bytes) -> int:
    """
    Extract scenario from UDP trigger JSON payload.
    UDP payload starts at offset 42 (Eth 14 + IP 20 + UDP 8).
    Defaults to scenario 1 if missing or invalid.
    """
    if len(pkt) < 42:
        return 1

    try:
        payload = pkt[42:]
        data = json.loads(payload.decode('utf-8', errors='ignore'))
        scenario = data.get("scenario", 1)

        # Validate scenario is in range
        if isinstance(scenario, int) and 1 <= scenario <= 4:
            return scenario
        else:
            print(f"[server] invalid scenario {scenario}, defaulting to 1", flush=True)
            return 1
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 1


def wait_for_trigger(sock: socket.socket) -> int:
    """
    Block until we see an incoming UDP packet destined for our port.
    Returns the scenario number from the trigger JSON.
    """
    while True:
        pkt = sock.recv(65535)
        if len(pkt) < 42:
            continue
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        if ethertype != 0x0800:
            continue
        protocol = pkt[23]
        if protocol != 17:  # UDP
            continue
        dst_port = struct.unpack("!H", pkt[36:38])[0]
        if dst_port == SRC_PORT:
            scenario = parse_trigger_json(pkt)
            return scenario


def handle_scenario_1(payload: bytes, sock: socket.socket) -> None:
    """UDP normal response"""
    frames = precompute_udp_frames(payload)
    print(f"[server] scenario 1: sending {len(frames)} UDP frames (normal)", flush=True)
    for frame in frames:
        sock.sendto(frame, (IFACE, 0))


def handle_scenario_2(payload: bytes, sock: socket.socket) -> None:
    """UDP response with tampered data (byte 50 in frame 15)"""
    frames = precompute_udp_frames(payload)

    # Tamper: XOR byte at offset 50 (which is inside the UDP payload for UDP frames)
    idx = min(15, len(frames) - 1)
    f = bytearray(frames[idx])
    f[50] ^= 0xFF
    frames[idx] = bytes(f)

    print(f"[server] scenario 2: sending {len(frames)} UDP frames (tampered at frame {idx} byte 50)", flush=True)
    for frame in frames:
        sock.sendto(frame, (IFACE, 0))


def handle_scenario_3(payload: bytes, sock: socket.socket) -> None:
    """TCP normal response"""
    frames = precompute_tcp_frames(payload)

    print(f"[server] scenario 3: waiting for TCP SYN ...", flush=True)
    # Wait for TCP SYN from client
    while True:
        pkt = sock.recv(65535)
        if len(pkt) < 54:
            continue
        protocol = pkt[23]
        if protocol != 6:  # TCP
            continue
        tcp_flags = pkt[47]
        if tcp_flags & 0x02:  # SYN flag
            break

    # Send SYN-ACK
    syn_ack = build_tcp_syn_ack()
    sock.sendto(syn_ack, (IFACE, 0))
    print(f"[server] scenario 3: sent SYN-ACK", flush=True)

    # Wait for ACK
    while True:
        pkt = sock.recv(65535)
        if len(pkt) < 54:
            continue
        protocol = pkt[23]
        if protocol != 6:  # TCP
            continue
        tcp_flags = pkt[47]
        if tcp_flags & 0x10:  # ACK flag
            break

    print(f"[server] scenario 3: received ACK, sending {len(frames)} TCP data frames (normal)", flush=True)

    # Send data frames
    for frame in frames:
        sock.sendto(frame, (IFACE, 0))

    # Send FIN-ACK (sequence continues from last data frame)
    last_seq = INITIAL_SEQ_SERVER + 1 + len(payload)
    fin_ack = build_tcp_fin_ack(last_seq, INITIAL_SEQ_CLIENT + 1)
    sock.sendto(fin_ack, (IFACE, 0))
    print(f"[server] scenario 3: sent FIN-ACK", flush=True)


def handle_scenario_4(payload: bytes, sock: socket.socket) -> None:
    """TCP response with tampered data (byte at offset 50 in frame 15 payload)"""
    frames = precompute_tcp_frames(payload)

    # Tamper: XOR byte at offset 50 in the TCP payload
    # For TCP frames: Eth(14) + IP(20) + TCP(20) + payload
    # So byte 50 in payload = byte 54 in frame
    idx = min(15, len(frames) - 1)
    f = bytearray(frames[idx])
    # Ensure we don't go out of bounds
    if len(f) > 54 + 50:
        f[54 + 50] ^= 0xFF
        frames[idx] = bytes(f)

    print(f"[server] scenario 4: waiting for TCP SYN ...", flush=True)
    # Wait for TCP SYN from client
    while True:
        pkt = sock.recv(65535)
        if len(pkt) < 54:
            continue
        protocol = pkt[23]
        if protocol != 6:  # TCP
            continue
        tcp_flags = pkt[47]
        if tcp_flags & 0x02:  # SYN flag
            break

    # Send SYN-ACK
    syn_ack = build_tcp_syn_ack()
    sock.sendto(syn_ack, (IFACE, 0))
    print(f"[server] scenario 4: sent SYN-ACK", flush=True)

    # Wait for ACK
    while True:
        pkt = sock.recv(65535)
        if len(pkt) < 54:
            continue
        protocol = pkt[23]
        if protocol != 6:  # TCP
            continue
        tcp_flags = pkt[47]
        if tcp_flags & 0x10:  # ACK flag
            break

    print(f"[server] scenario 4: received ACK, sending {len(frames)} TCP data frames (tampered at frame {idx})", flush=True)

    # Send data frames
    for frame in frames:
        sock.sendto(frame, (IFACE, 0))

    # Send FIN-ACK
    last_seq = INITIAL_SEQ_SERVER + 1 + len(payload)
    fin_ack = build_tcp_fin_ack(last_seq, INITIAL_SEQ_CLIENT + 1)
    sock.sendto(fin_ack, (IFACE, 0))
    print(f"[server] scenario 4: sent FIN-ACK", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default="/app/sample.json")
    parser.add_argument("--repeat", type=int, default=12)
    args = parser.parse_args()

    with open(args.json, "r") as f:
        data = json.load(f)

    response_bytes = (data["text"] * args.repeat).encode("utf-8")
    print(f"[server] payload: {len(response_bytes)} bytes", flush=True)

    # AF_PACKET raw socket — we supply full Ethernet frames
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((IFACE, 0))

    print("[server] waiting for trigger ...", flush=True)
    scenario = wait_for_trigger(sock)
    print(f"[server] trigger received with scenario {scenario}", flush=True)

    # Handle scenario
    if scenario == 1:
        handle_scenario_1(response_bytes, sock)
    elif scenario == 2:
        handle_scenario_2(response_bytes, sock)
    elif scenario == 3:
        handle_scenario_3(response_bytes, sock)
    elif scenario == 4:
        handle_scenario_4(response_bytes, sock)
    else:
        print(f"[server] unknown scenario {scenario}, defaulting to 1", flush=True)
        handle_scenario_1(response_bytes, sock)

    sock.close()
    print("[server] done", flush=True)


if __name__ == "__main__":
    main()
