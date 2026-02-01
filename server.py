"""
Warden server: precomputes deterministic Ethernet frames from a JSON payload,
listens for a UDP trigger on an AF_PACKET raw socket, then sends the
precomputed frames in order based on the scenario specified in the trigger.

Supports 5 scenarios:
1. UDP normal response
2. UDP response with tampered data
3. TCP normal response
4. TCP response with tampered data
5. TCP response with steganographic data in IP padding
"""

import struct
import socket
import json
import sys
import argparse
import time
from scapy.all import Ether, IP, UDP, TCP, Raw

# --- Configuration ---
IFACE = "veth-s"
SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"
SERVER_MAC = "02:00:0a:00:00:01"
CLIENT_MAC = "02:00:0a:00:00:02"
UDP_PORT = 5000
TCP_SERVER_PORT = 5000
TCP_CLIENT_PORT = 5001
MAX_PAYLOAD_UDP = 1472  # 1500 MTU - 20 (IP) - 8 (UDP)
MAX_PAYLOAD_TCP = 1460  # 1500 MTU - 20 (IP) - 20 (TCP)
MAX_PAYLOAD_TCP_STEGO = 1452  # 1500 MTU - 28 (IP with options) - 20 (TCP)
INITIAL_SEQ_SERVER = 1000
INITIAL_SEQ_CLIENT = 2000
TCP_WINDOW = 65535
TAMPER_OFFSET = 50  # Offset in the payload to tamper

# Scenario 5: Steganography via IP padding
STEG_MESSAGE = b"SECRET"  # Message to hide in IP padding
STEG_FRAMES_START = 10    # Start hiding message in frame 10
STEG_BYTES_PER_FRAME = 1  # Hide 1 byte per frame


def tamper_payload(payload: bytes, offset: int = TAMPER_OFFSET) -> bytes:
    """XOR a byte in the payload at the given offset"""
    if offset >= len(payload):
        return payload
    buf = bytearray(payload)
    buf[offset] ^= 0xFF
    return bytes(buf)


def build_udp_frame(ip_id: int, chunk: bytes) -> bytes:
    """Build UDP frame using Scapy"""
    pkt = Ether(dst=CLIENT_MAC, src=SERVER_MAC) / \
          IP(src=SERVER_IP, dst=CLIENT_IP, id=ip_id, flags="DF") / \
          UDP(sport=UDP_PORT, dport=UDP_PORT, chksum=0) / \
          Raw(load=chunk)
    return bytes(pkt)


def build_tcp_syn_ack(dport: int) -> bytes:
    """Server responds with SYN-ACK to client's SYN"""
    pkt = Ether(dst=CLIENT_MAC, src=SERVER_MAC) / \
          IP(src=SERVER_IP, dst=CLIENT_IP, id=0, flags="DF") / \
          TCP(sport=TCP_SERVER_PORT, dport=dport,
              flags="SA", seq=INITIAL_SEQ_SERVER,
              ack=INITIAL_SEQ_CLIENT + 1,
              window=TCP_WINDOW)
    return bytes(pkt)


def build_tcp_data_frame(ip_id: int, seq: int, dport: int, chunk: bytes) -> bytes:
    """Build TCP data frame with PSH+ACK flags"""
    pkt = Ether(dst=CLIENT_MAC, src=SERVER_MAC) / \
          IP(src=SERVER_IP, dst=CLIENT_IP, id=ip_id, flags="DF") / \
          TCP(sport=TCP_SERVER_PORT, dport=dport,
              flags="PA", seq=seq,
              ack=INITIAL_SEQ_CLIENT + 1,
              window=TCP_WINDOW) / \
          Raw(load=chunk)
    return bytes(pkt)


def build_tcp_data_frame_with_stego(ip_id: int, seq: int, dport: int, chunk: bytes, stego_byte: int) -> bytes:
    """Build TCP data frame with steganographic data in IP padding

    Args:
        ip_id: IP identification number
        seq: TCP sequence number
        dport: Destination port
        chunk: Payload data
        stego_byte: Byte value to hide in IP option padding

    Returns:
        Raw Ethernet frame bytes
    """
    # Build the base packet without options
    pkt = Ether(dst=CLIENT_MAC, src=SERVER_MAC) / \
          IP(src=SERVER_IP, dst=CLIENT_IP, id=ip_id, flags="DF") / \
          TCP(sport=TCP_SERVER_PORT, dport=dport,
              flags="PA", seq=seq,
              ack=INITIAL_SEQ_CLIENT + 1,
              window=TCP_WINDOW) / \
          Raw(load=chunk)

    # Convert to bytes and manually add IP options with steganographic data
    frame = bytearray(bytes(pkt))

    # IP header starts at byte 14 (after Ethernet)
    ip_start = 14

    # Standard IP header is 20 bytes, we'll extend it with 8 bytes of options
    # Current structure: Eth(14) + IP(20) + TCP(20+) + Data
    # New structure:     Eth(14) + IP(20) + Options(8) + TCP(20+) + Data

    # IP options (8 bytes): NOP(1) NOP(1) NOP(1) STEGO(1) NOP(1) NOP(1) NOP(1) NOP(1)
    # NOP option type = 0x01
    ip_options = bytes([0x01, 0x01, 0x01, stego_byte, 0x01, 0x01, 0x01, 0x01])

    # Extract IP header and update it
    ip_header = bytearray(frame[ip_start:ip_start + 20])

    # Update IHL (bits 0-3 of first byte): change from 5 to 7 (28 bytes total / 4)
    ip_header[0] = (ip_header[0] & 0xF0) | 0x07

    # Update total length (bytes 2-3): add 8 bytes for options
    total_len = struct.unpack("!H", ip_header[2:4])[0]
    new_total_len = total_len + 8
    ip_header[2:4] = struct.pack("!H", new_total_len)

    # Zero out checksum for recalculation
    ip_header[10:12] = bytes([0, 0])

    # Recalculate checksum over the modified header (without options)
    checksum = 0
    for i in range(0, 20, 2):
        checksum += struct.unpack("!H", ip_header[i:i+2])[0]
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (~checksum) & 0xFFFF
    ip_header[10:12] = struct.pack("!H", checksum)

    # Build new frame with options inserted
    new_frame = bytearray()
    new_frame.extend(frame[:ip_start])               # Ethernet header
    new_frame.extend(ip_header)                      # Modified IP header
    new_frame.extend(ip_options)                     # IP options
    new_frame.extend(frame[ip_start + 20:])          # TCP header and payload

    return bytes(new_frame)


def build_tcp_fin_ack(dport: int, seq: int, ack: int) -> bytes:
    """Server closes connection with FIN+ACK"""
    pkt = Ether(dst=CLIENT_MAC, src=SERVER_MAC) / \
          IP(src=SERVER_IP, dst=CLIENT_IP, id=0, flags="DF") / \
          TCP(sport=TCP_SERVER_PORT, dport=dport,
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


def precompute_tcp_frames(payload: bytes, client_dport: int) -> list[bytes]:
    """Precompute TCP data frames from payload"""
    frames = []
    offset = 0
    ip_id = 1
    seq = INITIAL_SEQ_SERVER + 1  # After SYN-ACK

    while offset < len(payload):
        chunk = payload[offset : offset + MAX_PAYLOAD_TCP]
        frames.append(build_tcp_data_frame(ip_id, seq, client_dport, chunk))
        offset += MAX_PAYLOAD_TCP
        seq += len(chunk)
        ip_id += 1

    return frames


def precompute_tcp_frames_with_stego(payload: bytes, client_dport: int) -> list[bytes]:
    """Precompute TCP data frames with steganographic IP padding

    Distributes STEG_MESSAGE across frames starting at STEG_FRAMES_START.
    Each frame hides one byte of the message in IP option padding.
    """
    frames = []
    offset = 0
    ip_id = 1
    seq = INITIAL_SEQ_SERVER + 1  # After SYN-ACK
    frame_num = 0
    steg_byte_idx = 0

    while offset < len(payload):
        # Determine if this frame should carry steganographic data
        is_stego_frame = (frame_num >= STEG_FRAMES_START and
                         steg_byte_idx < len(STEG_MESSAGE))

        # Use smaller payload size for frames with options to stay under MTU
        max_payload = MAX_PAYLOAD_TCP_STEGO if is_stego_frame else MAX_PAYLOAD_TCP
        chunk = payload[offset : offset + max_payload]

        if is_stego_frame:
            # Hide one byte of secret message
            stego_byte = STEG_MESSAGE[steg_byte_idx]
            frames.append(build_tcp_data_frame_with_stego(
                ip_id, seq, client_dport, chunk, stego_byte
            ))
            steg_byte_idx += 1
        else:
            # Normal frame without steganography
            frames.append(build_tcp_data_frame(ip_id, seq, client_dport, chunk))

        offset += max_payload
        seq += len(chunk)
        ip_id += 1
        frame_num += 1

    return frames


def parse_trigger_json(pkt) -> int:
    """
    Extract scenario from UDP trigger JSON payload using Scapy.
    Returns scenario number (1-5), defaults to 1 if invalid.
    """
    try:
        # Parse with Scapy to handle variable headers safely
        if UDP not in pkt:
            return 1

        udp_pkt = pkt[UDP]
        payload = bytes(udp_pkt.payload)

        data = json.loads(payload.decode('utf-8', errors='ignore'))
        scenario = data.get("scenario", 1)

        # Validate scenario is in range
        if isinstance(scenario, int) and 1 <= scenario <= 5:
            return scenario
        else:
            print(f"[server] invalid scenario {scenario}, defaulting to 1", flush=True)
            return 1
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        return 1


def wait_for_trigger(sock: socket.socket) -> tuple[int, int]:
    """
    Block until we see an incoming UDP trigger.
    Returns (scenario, client_sport) tuple.
    """
    while True:
        frame_bytes = sock.recv(65535)

        try:
            pkt = Ether(frame_bytes)

            # Verify it's IPv4 UDP
            if IP not in pkt or UDP not in pkt:
                continue

            ip_pkt = pkt[IP]
            udp_pkt = pkt[UDP]

            # Check if it's destined for our UDP port
            if udp_pkt.dport != UDP_PORT:
                continue

            # Extract client's source port for later use
            client_sport = udp_pkt.sport

            # Parse scenario from JSON payload
            scenario = parse_trigger_json(pkt)

            print(f"[server] trigger received from {ip_pkt.src}:{client_sport} with scenario {scenario}", flush=True)
            return scenario, client_sport

        except Exception as e:
            # Ignore frames that don't parse or don't match our criteria
            continue


def wait_for_tcp_syn(sock: socket.socket, client_sport: int) -> int:
    """
    Wait for a TCP SYN from the client.
    Returns the client's source port from the SYN packet.
    """
    while True:
        frame_bytes = sock.recv(65535)

        try:
            pkt = Ether(frame_bytes)

            # Verify it's IPv4 TCP
            if IP not in pkt or TCP not in pkt:
                continue

            ip_pkt = pkt[IP]
            tcp_pkt = pkt[TCP]

            # Check if it's from the client
            if ip_pkt.src != CLIENT_IP:
                continue

            # Check if it's a SYN
            if not (tcp_pkt.flags & 0x02):  # SYN flag
                continue

            # Found valid SYN
            return tcp_pkt.sport

        except Exception:
            continue


def wait_for_tcp_ack(sock: socket.socket, client_sport: int) -> bool:
    """
    Wait for a TCP ACK from the client.
    Returns True if ACK received, False on timeout.
    """
    sock.settimeout(5.0)
    while True:
        try:
            frame_bytes = sock.recv(65535)

            pkt = Ether(frame_bytes)

            # Verify it's IPv4 TCP from client
            if IP not in pkt or TCP not in pkt:
                continue

            ip_pkt = pkt[IP]
            tcp_pkt = pkt[TCP]

            if ip_pkt.src != CLIENT_IP or tcp_pkt.sport != client_sport:
                continue

            # Check if it's an ACK (without SYN/FIN)
            flags = tcp_pkt.flags
            if (flags & 0x10) and not (flags & 0x02) and not (flags & 0x01):
                return True

        except socket.timeout:
            return False
        except Exception:
            continue


def handle_scenario_1(payload: bytes, sock: socket.socket) -> None:
    """UDP normal response"""
    frames = precompute_udp_frames(payload)
    print(f"[server] scenario 1: sending {len(frames)} UDP frames (normal)", flush=True)
    for frame in frames:
        sock.sendto(frame, (IFACE, 0))


def handle_scenario_2(payload: bytes, sock: socket.socket) -> None:
    """UDP response with tampered data"""
    # Tamper at payload level before building frames
    tampered_payload = tamper_payload(payload)
    frames = precompute_udp_frames(tampered_payload)
    print(f"[server] scenario 2: sending {len(frames)} UDP frames (tampered at byte {TAMPER_OFFSET})", flush=True)
    for frame in frames:
        sock.sendto(frame, (IFACE, 0))


def handle_scenario_3(payload: bytes, sock: socket.socket, client_sport: int) -> None:
    """TCP normal response"""
    print(f"[server] scenario 3: waiting for TCP SYN ...", flush=True)
    client_dport = wait_for_tcp_syn(sock, client_sport)

    # Send SYN-ACK
    syn_ack = build_tcp_syn_ack(client_dport)
    sock.sendto(syn_ack, (IFACE, 0))
    print(f"[server] scenario 3: sent SYN-ACK", flush=True)

    # Wait for ACK
    if not wait_for_tcp_ack(sock, client_dport):
        print(f"[server] scenario 3: timeout waiting for ACK", flush=True)
        return

    print(f"[server] scenario 3: received ACK, sending TCP data frames (normal)", flush=True)

    # Build and send frames
    frames = precompute_tcp_frames(payload, client_dport)
    for frame in frames:
        sock.sendto(frame, (IFACE, 0))

    # Send FIN-ACK
    last_seq = INITIAL_SEQ_SERVER + 1 + len(payload)
    fin_ack = build_tcp_fin_ack(client_dport, last_seq, INITIAL_SEQ_CLIENT + 1)
    sock.sendto(fin_ack, (IFACE, 0))
    print(f"[server] scenario 3: sent FIN-ACK", flush=True)

    time.sleep(0.1)


def handle_scenario_4(payload: bytes, sock: socket.socket, client_sport: int) -> None:
    """TCP response with tampered data"""
    # Tamper at payload level before building frames
    tampered_payload = tamper_payload(payload)

    print(f"[server] scenario 4: waiting for TCP SYN ...", flush=True)
    client_dport = wait_for_tcp_syn(sock, client_sport)

    # Send SYN-ACK
    syn_ack = build_tcp_syn_ack(client_dport)
    sock.sendto(syn_ack, (IFACE, 0))
    print(f"[server] scenario 4: sent SYN-ACK", flush=True)

    # Wait for ACK
    if not wait_for_tcp_ack(sock, client_dport):
        print(f"[server] scenario 4: timeout waiting for ACK", flush=True)
        return

    print(f"[server] scenario 4: received ACK, sending TCP data frames (tampered at byte {TAMPER_OFFSET})", flush=True)

    # Build and send frames
    frames = precompute_tcp_frames(tampered_payload, client_dport)
    for frame in frames:
        sock.sendto(frame, (IFACE, 0))

    # Send FIN-ACK
    last_seq = INITIAL_SEQ_SERVER + 1 + len(tampered_payload)
    fin_ack = build_tcp_fin_ack(client_dport, last_seq, INITIAL_SEQ_CLIENT + 1)
    sock.sendto(fin_ack, (IFACE, 0))
    print(f"[server] scenario 4: sent FIN-ACK", flush=True)

    time.sleep(0.1)


def handle_scenario_5(payload: bytes, sock: socket.socket, client_sport: int) -> None:
    """TCP response with steganographic data in IP padding

    Normal TCP connection but with secret message hidden in IP option padding
    bytes. This demonstrates covert channel detection.
    """
    print(f"[server] scenario 5: waiting for TCP SYN ...", flush=True)
    client_dport = wait_for_tcp_syn(sock, client_sport)

    # Send SYN-ACK (normal, no steganography in handshake)
    syn_ack = build_tcp_syn_ack(client_dport)
    sock.sendto(syn_ack, (IFACE, 0))
    print(f"[server] scenario 5: sent SYN-ACK", flush=True)

    # Wait for ACK
    if not wait_for_tcp_ack(sock, client_dport):
        print(f"[server] scenario 5: timeout waiting for ACK", flush=True)
        return

    print(f"[server] scenario 5: received ACK, sending TCP data frames with IP padding steganography", flush=True)
    print(f"[server] scenario 5: hiding message '{STEG_MESSAGE.decode()}' in IP padding", flush=True)

    # Build and send frames with steganographic IP padding
    frames = precompute_tcp_frames_with_stego(payload, client_dport)
    for frame in frames:
        sock.sendto(frame, (IFACE, 0))

    # Send FIN-ACK
    last_seq = INITIAL_SEQ_SERVER + 1 + len(payload)
    fin_ack = build_tcp_fin_ack(client_dport, last_seq, INITIAL_SEQ_CLIENT + 1)
    sock.sendto(fin_ack, (IFACE, 0))
    print(f"[server] scenario 5: sent FIN-ACK", flush=True)

    time.sleep(0.1)


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
    scenario, client_sport = wait_for_trigger(sock)

    # Handle scenario
    if scenario == 1:
        handle_scenario_1(response_bytes, sock)
    elif scenario == 2:
        handle_scenario_2(response_bytes, sock)
    elif scenario == 3:
        handle_scenario_3(response_bytes, sock, client_sport)
    elif scenario == 4:
        handle_scenario_4(response_bytes, sock, client_sport)
    elif scenario == 5:
        handle_scenario_5(response_bytes, sock, client_sport)
    else:
        print(f"[server] unknown scenario {scenario}, defaulting to 1", flush=True)
        handle_scenario_1(response_bytes, sock)

    sock.close()
    print("[server] done", flush=True)


if __name__ == "__main__":
    main()
