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


def read_pcap_with_timestamps(path: str) -> list[tuple[float, bytes]]:
    """Read PCAP and return list of (timestamp, packet_data)"""
    packets = []
    with open(path, "rb") as f:
        ghdr = f.read(24)
        if len(ghdr) < 24:
            raise ValueError(f"Truncated pcap: {path}")
        magic = struct.unpack("<I", ghdr[:4])[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
            time_res = 1e-6 # Microseconds
        elif magic == 0xD4C3B2A1:
            endian = ">"
            time_res = 1e-6
        elif magic == 0xA1B23C4D: # Nanosecond pcap
            endian = "<"
            time_res = 1e-9
        else:
            # Try to continue typically
            endian = "<"
            time_res = 1e-6

        while True:
            phdr = f.read(16)
            if len(phdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", phdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            
            timestamp = ts_sec + (ts_usec * time_res)
            packets.append((timestamp, data))
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


def analyze_timing_channel(pcap_path: str):
    """Analyze Inter-Packet Delays (IPDs) to detect timing channels"""
    print(f"Analyzing timing for: {pcap_path}")
    packets = read_pcap_with_timestamps(pcap_path)
    
    # Filter for data frames from server (heuristic: typical payload size or port)
    # The server sends from 10.0.0.1
    
    timestamps = []
    for ts, pkt in packets:
        if is_data_frame(pkt):
            # Try to check if src is server (10.0.0.1)
            # IP src offset is 26=14+12
            if len(pkt) > 30:
                ethertype = struct.unpack("!H", pkt[12:14])[0]
                if ethertype == 0x0800:
                    ip_src = pkt[26:30]
                    if ip_src == b'\x0a\x00\x00\x01': # 10.0.0.1
                        timestamps.append(ts)
    
    if len(timestamps) < 2:
        print("Not enough packets for timing analysis")
        return

    # Calculate IPDs
    ipds = []
    for i in range(1, len(timestamps)):
        diff = timestamps[i] - timestamps[i-1]
        ipds.append(diff)
        
    # Statistics
    avg = sum(ipds) / len(ipds)
    variance = sum((x - avg) ** 2 for x in ipds) / len(ipds)
    
    print(f"Packet Count: {len(timestamps)}")
    print(f"Mean IPD: {avg*1000:.4f} ms")
    print(f"Variance: {variance*1e6:.6f} (scaled)")
    
    # Bandwidth Estimation
    # 1 bit per interval
    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
    bitrate = (len(timestamps) - 1) / duration if duration > 0 else 0
    print(f"Estimated Bandwidth: {bitrate:.2f} bps (raw)")
    
    # Check for modulation (bi-modal distribution around 200us and 500us)
    # 200us = 0.0002, 500us = 0.0005
    
    count_200 = 0
    count_500 = 0
    count_1000 = 0 # Fuzzy barrier 1ms
    
    for d in ipds:
        if 0.00015 < d < 0.00025:
            count_200 += 1
        elif 0.00045 < d < 0.00055:
            count_500 += 1
        elif 0.0009 < d < 0.0011:
            count_1000 += 1
            
    print(f"Distribution:")
    print(f"  ~200us: {count_200}")
    print(f"  ~500us: {count_500}")
    print(f"  ~1ms:   {count_1000}")
    
    if count_1000 > len(ipds) * 0.8:
        print("RESULT: Quantized (Fuzzy Barrier Active) - SECURE")
    elif (count_200 + count_500) > len(ipds) * 0.5:
        print("RESULT: Modulated (Timing Channel Detected) - VULNERABLE")
    else:
        print("RESULT: Indeterminate / Noise")
        
    return {
        "count": len(timestamps),
        "mean_ipd": avg,
        "variance": variance,
        "duration": timestamps[-1] - timestamps[0] if timestamps else 0
    }


def main() -> None:
    # Parse arguments
    zero_ip_options = False
    timing_analysis = False
    cap1_path = None
    cap2_path = None

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--zero-ip-options":
            zero_ip_options = True
        elif arg == "--timing-analysis":
            timing_analysis = True
        elif cap1_path is None:
            cap1_path = arg
        elif cap2_path is None:
            cap2_path = arg

    if timing_analysis:
        if cap1_path is None:
             print("Usage: analyze.py --timing-analysis <capture.pcap> [capture2.pcap]")
             sys.exit(2)
        stats1 = analyze_timing_channel(cap1_path)
        if cap2_path:
            print("-" * 40)
            stats2 = analyze_timing_channel(cap2_path)
            
            # Comparative Analysis
            if stats1 and stats2:
                print("=" * 40)
                print("COMPARATIVE LATENCY ANALYSIS")
                print("=" * 40)
                
                dur1 = stats1["duration"]
                dur2 = stats2["duration"]
                mean1 = stats1["mean_ipd"]
                mean2 = stats2["mean_ipd"]
                
                diff_dur = dur2 - dur1
                diff_mean = mean2 - mean1
                
                # Assume Capture 2 is the "barrier enabled" one if it has higher variance/duration
                # But just reporting difference is safer
                
                print(f"Total Duration:")
                print(f"  Capture 1: {dur1*1000:.2f} ms")
                print(f"  Capture 2: {dur2*1000:.2f} ms")
                print(f"  Delta:    {diff_dur*1000:+.2f} ms ({((dur2-dur1)/dur1)*100:+.1f}%)")
                
                print(f"\nAverage Inter-Packet Delay:")
                print(f"  Capture 1: {mean1*1000:.4f} ms")
                print(f"  Capture 2: {mean2*1000:.4f} ms")
                print(f"  Added Latency: {diff_mean*1000:+.4f} ms/packet")
                
                print(f"\nBandwidth Impact:")
                bps1 = (stats1['count'] - 1) / dur1 if dur1 > 0 else 0
                bps2 = (stats2['count'] - 1) / dur2 if dur2 > 0 else 0
                print(f"  Capture 1: {bps1:.2f} bps")
                print(f"  Capture 2: {bps2:.2f} bps")
                print(f"  Reduction: {abs(bps1-bps2):.2f} bps ({abs((bps2-bps1)/bps1)*100:.1f}%)")
                
                print(f"\nTrade-off Assessment:")
                if diff_mean > 0:
                    print(f"  Security Cost: The barrier adds approx {diff_mean*1000:.2f} ms of latency per packet.")
                    print(f"  Throughput Impact: Reduced by approx {abs((1/mean2 - 1/mean1)/(1/mean1))*100:.1f}%.")
                else:
                    print(f"  Performance: No significant latency penalty detected (or ordering reversed).")

        sys.exit(0)

    if cap1_path is None or cap2_path is None:
        print(f"usage: {sys.argv[0]} [--zero-ip-options] [--timing-analysis] <cap1.pcap> <cap2.pcap>")
        print(f"")
        print(f"  --zero-ip-options: Zero out IP options/padding (defeats steganography detection)")
        print(f"  --timing-analysis: Analyze Inter-Packet Delays instead of content")
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
