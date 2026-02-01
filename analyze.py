"""
Compare two pcap files after normalizing volatile fields.
Zeroes out: IP identification, IP header checksum, UDP checksum.
Optional: Zero IP options/padding to defeat steganography detection.
"""

import struct
import hashlib
import sys
from scapy.all import Ether, IP, UDP, TCP


def read_pcap(path: str) -> list[bytes]:
    packets = []
    with open(path, "rb") as f:
        ghdr = f.read(24)
        if len(ghdr) < 24:
            raise ValueError(f"Truncated pcap: {path}")
        magic = struct.unpack("<I", ghdr[:4])[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
        elif magic == 0xD4C3B2A1:
            endian = ">"
        else:
            raise ValueError(f"Bad magic in {path}: {hex(magic)}")

        while True:
            phdr = f.read(16)
            if len(phdr) < 16:
                break
            _, _, incl_len, _ = struct.unpack(endian + "IIII", phdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            packets.append(data)
    return packets


def extract_tcp_payload(pkt: bytes) -> bytes:
    """Extract payload from TCP packet, return empty if no payload"""
    if len(pkt) < 54:
        return b""

    # Check ethertype
    ethertype = struct.unpack("!H", pkt[12:14])[0]
    if ethertype != 0x0800:
        return b""

    # Get IP header and protocol
    ip = 14
    proto = pkt[ip + 9]
    if proto != 6:  # Not TCP
        return b""

    # Get TCP header offset and flags
    ihl = (pkt[ip] & 0x0F) * 4
    tcp = ip + ihl
    if len(pkt) < tcp + 20:
        return b""

    # TCP data offset is in upper 4 bits of offset field (offset 12)
    tcp_data_offset = (pkt[tcp + 12] >> 4) * 4
    payload_start = tcp + tcp_data_offset

    if len(pkt) <= payload_start:
        return b""

    return pkt[payload_start:]


def normalize(pkt: bytes, zero_ip_options: bool = False) -> bytes:
    """Normalize packet by zeroing volatile fields using Scapy for parsing.

    Args:
        pkt: Raw packet bytes
        zero_ip_options: If True, zero out IP options/padding area (defeats steganography)

    Returns:
        Normalized packet bytes
    """
    if len(pkt) < 34:
        return pkt

    buf = bytearray(pkt)

    # Use Scapy to parse and understand the packet structure
    try:
        eth_pkt = Ether(pkt)
    except Exception:
        # If Scapy can't parse, just do basic checks
        ethertype = struct.unpack("!H", buf[12:14])[0]
        if ethertype != 0x0800:
            return bytes(buf)
    else:
        # Scapy successfully parsed - use its information
        if IP not in eth_pkt:
            return bytes(buf)

    # Ethertype check
    ethertype = struct.unpack("!H", buf[12:14])[0]
    if ethertype != 0x0800:
        return bytes(buf)

    ip = 14  # start of IP header

    # Zero IP identification (offset 4-5)
    buf[ip + 4] = 0
    buf[ip + 5] = 0

    # Zero IP header checksum (offset 10-11)
    buf[ip + 10] = 0
    buf[ip + 11] = 0

    ihl = (buf[ip] & 0x0F) * 4
    proto = buf[ip + 9]

    # Zero IP options if requested (defeat steganography)
    # This removes the IP options entirely, making the presence of steganography undetectable
    if zero_ip_options and ihl > 20:
        # Remove the IP options by reconstructing the packet without them
        eth_and_ip = buf[:ip + 20]  # Ethernet + IP header (without options)
        rest = buf[ip + ihl:]        # Everything after IP header

        # Rebuild buffer without IP options
        buf = bytearray(eth_and_ip + rest)

        # Update IP header fields
        # Set IHL to 5 (standard 20-byte header)
        buf[ip] = (buf[ip] & 0xF0) | 0x05

        # Update total length to remove option bytes
        options_removed = ihl - 20
        total_len = struct.unpack("!H", buf[ip + 2:ip + 4])[0]
        new_total_len = total_len - options_removed
        buf[ip + 2:ip + 4] = struct.pack("!H", new_total_len)

        # Zero the checksum since it will change
        buf[ip + 10:ip + 12] = bytes([0, 0])

        # Re-parse for the rest of the function to work correctly
        ihl = 20
        proto = buf[ip + 9]

    # Zero UDP checksum (offset 6-7 of UDP header)
    if proto == 17 and len(buf) >= ip + ihl + 8:
        udp = ip + ihl
        buf[udp + 6] = 0
        buf[udp + 7] = 0

    # Zero TCP checksum (offset 16-17 of TCP header)
    if proto == 6 and len(buf) >= ip + ihl + 20:
        tcp = ip + ihl
        buf[tcp + 16] = 0
        buf[tcp + 17] = 0

    return bytes(buf)

def is_data_frame(pkt: bytes) -> bool:
    """Check if packet has actual data payload (not just control)"""
    # UDP frames: always have data
    # TCP frames: must have non-empty payload
    if len(pkt) < 42:
        return False

    ethertype = struct.unpack("!H", pkt[12:14])[0]
    if ethertype != 0x0800:
        return False

    proto = pkt[23]
    if proto == 17:  # UDP
        return True
    elif proto == 6:  # TCP
        payload = extract_tcp_payload(pkt)
        return len(payload) > 0

    return False


def simple_warden(pkts: list[bytes], zero_ip_options: bool = False):
    # Filter to only data frames (skip TCP control packets)
    data_frames = [p for p in pkts if is_data_frame(p)]
    return [normalize(p, zero_ip_options=zero_ip_options) for p in data_frames]


def main() -> None:
    # Parse arguments
    zero_ip_options = False
    cap1_path = None
    cap2_path = None

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--zero-ip-options":
            zero_ip_options = True
        elif cap1_path is None:
            cap1_path = arg
        elif cap2_path is None:
            cap2_path = arg

    if cap1_path is None or cap2_path is None:
        print(f"usage: {sys.argv[0]} [--zero-ip-options] <cap1.pcap> <cap2.pcap>")
        print(f"")
        print(f"  --zero-ip-options: Zero out IP options/padding (defeats steganography detection)")
        sys.exit(2)

    pkts1 = read_pcap(cap1_path)
    pkts2 = read_pcap(cap2_path)

    print(f"capture 1: {len(pkts1)} packets")
    print(f"capture 2: {len(pkts2)} packets")

    norm1 = simple_warden(pkts1, zero_ip_options=zero_ip_options)
    norm2 = simple_warden(pkts2, zero_ip_options=zero_ip_options)

    print(f"capture 1: {len(norm1)} data frames after filtering")
    print(f"capture 2: {len(norm2)} data frames after filtering")
    if zero_ip_options:
        print(f"[IP options zeroed - steganography detection defeated]")

    h1 = hashlib.sha256(b"".join(norm1)).hexdigest()
    h2 = hashlib.sha256(b"".join(norm2)).hexdigest()

    print(f"hash 1: {h1}")
    print(f"hash 2: {h2}")

    if h1 == h2:
        print("PASS — normalized egress traffic is identical across both runs")
    else:
        print("FAIL — traffic differs")
        for i in range(min(len(norm1), len(norm2))):
            if norm1[i] != norm2[i]:
                print(f"  packet {i} differs")
                # Show first differing byte
                for j in range(min(len(norm1[i]), len(norm2[i]))):
                    if norm1[i][j] != norm2[i][j]:
                        print(f"    first diff at byte {j}: 0x{norm1[i][j]:02x} vs 0x{norm2[i][j]:02x}")
                        # Debug: show more context
                        if j < 60:
                            start = max(0, j - 5)
                            end = min(len(norm1[i]), j + 10)
                            print(f"    context 1: {norm1[i][start:end].hex()}")
                            print(f"    context 2: {norm2[i][start:end].hex()}")
                        break
        if len(norm1) != len(norm2):
            print(f"  packet count: {len(norm1)} vs {len(norm2)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
