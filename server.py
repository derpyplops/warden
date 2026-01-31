"""
Warden server: precomputes deterministic Ethernet frames from a JSON payload,
listens for a UDP trigger on an AF_PACKET raw socket, then sends the
precomputed frames in order.
"""

import struct
import socket
import json
import sys
import argparse

# --- Configuration ---
IFACE = "veth-s"
SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"
SERVER_MAC = bytes.fromhex("02000a000001")  # 02:00:0a:00:00:01
CLIENT_MAC = bytes.fromhex("02000a000002")  # 02:00:0a:00:00:02
SRC_PORT = 5000
DST_PORT = 5000
MAX_PAYLOAD = 1472  # 1500 MTU - 20 (IP) - 8 (UDP)


def ip_checksum(header_bytes: bytes) -> int:
    if len(header_bytes) % 2:
        header_bytes += b"\x00"
    s = 0
    for i in range(0, len(header_bytes), 2):
        s += (header_bytes[i] << 8) | header_bytes[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_ip_header(payload_len: int, ip_id: int) -> bytes:
    version_ihl = 0x45
    tos = 0
    total_len = 20 + 8 + payload_len
    flags_frag = 0x4000  # DF bit set
    ttl = 64
    protocol = 17  # UDP
    src = socket.inet_aton(SERVER_IP)
    dst = socket.inet_aton(CLIENT_IP)

    # First pass: checksum field = 0
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len,
        ip_id, flags_frag,
        ttl, protocol, 0,
        src, dst,
    )
    csum = ip_checksum(hdr)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len,
        ip_id, flags_frag,
        ttl, protocol, csum,
        src, dst,
    )


def build_udp_header(payload_len: int) -> bytes:
    udp_len = 8 + payload_len
    return struct.pack("!HHHH", SRC_PORT, DST_PORT, udp_len, 0)  # checksum = 0 (valid in IPv4)


def build_frame(ip_id: int, chunk: bytes) -> bytes:
    ip_hdr = build_ip_header(len(chunk), ip_id)
    udp_hdr = build_udp_header(len(chunk))
    eth = CLIENT_MAC + SERVER_MAC + struct.pack("!H", 0x0800)
    return eth + ip_hdr + udp_hdr + chunk


def precompute_frames(payload: bytes) -> list[bytes]:
    frames = []
    offset = 0
    ip_id = 0
    while offset < len(payload):
        chunk = payload[offset : offset + MAX_PAYLOAD]
        frames.append(build_frame(ip_id, chunk))
        offset += MAX_PAYLOAD
        ip_id += 1
    return frames


def wait_for_trigger(sock: socket.socket) -> None:
    """Block until we see an incoming UDP packet destined for our port."""
    while True:
        pkt = sock.recv(65535)
        if len(pkt) < 42:
            continue
        ethertype = struct.unpack("!H", pkt[12:14])[0]
        if ethertype != 0x0800:
            continue
        protocol = pkt[23]
        if protocol != 17:
            continue
        dst_port = struct.unpack("!H", pkt[36:38])[0]
        if dst_port == SRC_PORT:
            return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default="/app/sample.json")
    parser.add_argument("--repeat", type=int, default=1000)
    parser.add_argument("--tamper", action="store_true",
                        help="flip one byte in frame 15 to simulate steganography")
    args = parser.parse_args()

    with open(args.json, "r") as f:
        data = json.load(f)

    response_bytes = (data["text"] * args.repeat).encode("utf-8")
    print(f"[server] payload: {len(response_bytes)} bytes", flush=True)

    frames = precompute_frames(response_bytes)
    print(f"[server] precomputed {len(frames)} frames", flush=True)

    if args.tamper:
        # Mutate one payload byte in frame 15 (XOR with 0xff)
        idx = min(15, len(frames) - 1)
        f = bytearray(frames[idx])
        f[50] ^= 0xFF  # byte 50 is inside the UDP payload
        frames[idx] = bytes(f)
        print(f"[server] TAMPERED frame {idx} byte 50", flush=True)

    # AF_PACKET raw socket — we supply full Ethernet frames
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((IFACE, 0))

    print("[server] waiting for trigger ...", flush=True)
    wait_for_trigger(sock)
    print("[server] trigger received, sending frames ...", flush=True)

    for frame in frames:
        sock.sendto(frame, (IFACE, 0))

    print(f"[server] sent {len(frames)} frames", flush=True)
    sock.close()


if __name__ == "__main__":
    main()
