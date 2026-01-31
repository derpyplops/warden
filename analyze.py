"""
Compare two pcap files after normalizing volatile fields.
Zeroes out: IP identification, IP header checksum, UDP checksum.
"""

import struct
import hashlib
import sys


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


def normalize(pkt: bytes) -> bytes:
    if len(pkt) < 34:
        return pkt

    buf = bytearray(pkt)

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

    # Zero UDP checksum (offset 6-7 of UDP header)
    if proto == 17 and len(buf) >= ip + ihl + 8:
        udp = ip + ihl
        buf[udp + 6] = 0
        buf[udp + 7] = 0

    return bytes(buf)

def simple_warden(pkts: list[bytes]):
    return [normalize(p) for p in pkts]


def main() -> None:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <cap1.pcap> <cap2.pcap>")
        sys.exit(2)

    pkts1 = read_pcap(sys.argv[1])
    pkts2 = read_pcap(sys.argv[2])

    print(f"capture 1: {len(pkts1)} packets")
    print(f"capture 2: {len(pkts2)} packets")

    norm1 = simple_warden(pkts1)
    norm2 = simple_warden(pkts2)

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
                        break
        if len(norm1) != len(norm2):
            print(f"  packet count: {len(norm1)} vs {len(norm2)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
