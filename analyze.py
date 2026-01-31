"""
Packet analysis and scrubbing for the Warden protocol.

This module provides:
- Pcap reading
- Packet normalization (for comparison, zeroes volatile fields)
- Active warden scrubbing (replaces fields with canonical/RNG values)
- Connection tracking for server source port enforcement
"""

import struct
import hashlib
import sys
import time
from typing import Optional
from dataclasses import dataclass

# Import coin flip RNG (optional, for scrubbing)
try:
    from coin_flip import CoinFlipRNG
except ImportError:
    CoinFlipRNG = None  # type: ignore


# ============================================================================
# Constants
# ============================================================================

# Demo network configuration
SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"

# Canonical values for scrubbing
CANONICAL_TTL = 64

# Ethernet frame offsets
ETH_DST = 0       # Destination MAC (6 bytes)
ETH_SRC = 6       # Source MAC (6 bytes)
ETH_TYPE = 12     # EtherType (2 bytes)
ETH_HEADER_LEN = 14

# IPv4 header offsets (relative to IP header start)
IP_VERSION_IHL = 0   # Version + IHL (1 byte)
IP_TOS = 1           # Type of Service (1 byte)
IP_TOTAL_LEN = 2     # Total Length (2 bytes)
IP_ID = 4            # Identification (2 bytes)
IP_FLAGS_FRAG = 6    # Flags + Fragment Offset (2 bytes)
IP_TTL = 8           # Time to Live (1 byte)
IP_PROTOCOL = 9      # Protocol (1 byte)
IP_CHECKSUM = 10     # Header Checksum (2 bytes)
IP_SRC = 12          # Source Address (4 bytes)
IP_DST = 16          # Destination Address (4 bytes)

# UDP header offsets (relative to UDP header start)
UDP_SRC_PORT = 0     # Source Port (2 bytes)
UDP_DST_PORT = 2     # Destination Port (2 bytes)
UDP_LENGTH = 4       # Length (2 bytes)
UDP_CHECKSUM = 6     # Checksum (2 bytes)
UDP_HEADER_LEN = 8

# Protocol numbers
PROTO_UDP = 17
PROTO_TCP = 6

# EtherType values
ETHERTYPE_IPV4 = 0x0800


# ============================================================================
# Pcap Reading
# ============================================================================

def read_pcap(path: str) -> list[bytes]:
    """Read packets from a pcap file."""
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


# ============================================================================
# Checksum Computation
# ============================================================================

def compute_ip_checksum(ip_header: bytes) -> int:
    """
    Compute IPv4 header checksum.
    
    The checksum field should be zeroed before calling this function.
    """
    if len(ip_header) % 2:
        ip_header = ip_header + b'\x00'
    
    total = 0
    for i in range(0, len(ip_header), 2):
        word = (ip_header[i] << 8) | ip_header[i + 1]
        total += word
    
    # Fold 32-bit sum to 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    
    return (~total) & 0xFFFF


def compute_udp_checksum(src_ip: bytes, dst_ip: bytes, udp_header: bytes, payload: bytes) -> int:
    """
    Compute UDP checksum including the pseudo-header.
    
    The UDP checksum field should be zeroed before calling this function.
    
    Pseudo-header format:
        - Source IP (4 bytes)
        - Destination IP (4 bytes)
        - Zero (1 byte)
        - Protocol (1 byte, = 17 for UDP)
        - UDP Length (2 bytes)
    """
    udp_length = len(udp_header) + len(payload)
    
    # Build pseudo-header
    pseudo_header = (
        src_ip +
        dst_ip +
        struct.pack("!BBH", 0, PROTO_UDP, udp_length)
    )
    
    # Concatenate pseudo-header, UDP header, and payload
    data = pseudo_header + udp_header + payload
    
    # Pad to even length
    if len(data) % 2:
        data = data + b'\x00'
    
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word
    
    # Fold 32-bit sum to 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    
    checksum = (~total) & 0xFFFF
    
    # UDP checksum of 0 is transmitted as 0xFFFF (RFC 768)
    if checksum == 0:
        checksum = 0xFFFF
    
    return checksum


# ============================================================================
# Connection Tracking
# ============================================================================

@dataclass
class ConnectionEntry:
    """Entry in the connection tracking table."""
    expected_src_port: int
    timestamp: float


class ConnectionTracker:
    """
    Tracks connections to enforce server source port consistency.
    
    When a client sends a request to the server on port X, any response
    from the server to that client must come from port X. This prevents
    the server from using source port selection as a covert channel.
    
    The tracker maintains a table mapping (client_ip, client_port) to
    the expected server source port. Entries expire after a timeout
    to handle UDP's lack of explicit connection termination.
    """
    
    def __init__(self, timeout_seconds: float = 30.0):
        """
        Initialize the connection tracker.
        
        Args:
            timeout_seconds: How long to keep entries before expiry.
        """
        self.timeout = timeout_seconds
        self._table: dict[tuple[str, int], ConnectionEntry] = {}
    
    def record_inbound(self, client_ip: str, client_port: int, server_port: int) -> None:
        """
        Record an inbound request from client to server.
        
        Args:
            client_ip: Client's IP address
            client_port: Client's source port
            server_port: Server port the request was sent to
        """
        key = (client_ip, client_port)
        self._table[key] = ConnectionEntry(
            expected_src_port=server_port,
            timestamp=time.time(),
        )
    
    def get_expected_src_port(self, client_ip: str, client_port: int) -> Optional[int]:
        """
        Get the expected server source port for a response to this client.
        
        Args:
            client_ip: Client's IP address
            client_port: Client's port (destination of the response)
        
        Returns:
            Expected server source port, or None if no matching entry.
        """
        key = (client_ip, client_port)
        entry = self._table.get(key)
        
        if entry is None:
            return None
        
        # Check for expiry
        if time.time() - entry.timestamp > self.timeout:
            del self._table[key]
            return None
        
        return entry.expected_src_port
    
    def cleanup_expired(self) -> int:
        """
        Remove expired entries from the table.
        
        Returns:
            Number of entries removed.
        """
        now = time.time()
        expired_keys = [
            key for key, entry in self._table.items()
            if now - entry.timestamp > self.timeout
        ]
        for key in expired_keys:
            del self._table[key]
        return len(expired_keys)
    
    @property
    def size(self) -> int:
        """Number of entries in the table."""
        return len(self._table)


# ============================================================================
# Packet Parsing Helpers
# ============================================================================

def parse_ip_addresses(buf: bytearray, ip_start: int) -> tuple[str, str]:
    """Extract source and destination IP addresses as strings."""
    src_bytes = buf[ip_start + IP_SRC : ip_start + IP_SRC + 4]
    dst_bytes = buf[ip_start + IP_DST : ip_start + IP_DST + 4]
    src_ip = ".".join(str(b) for b in src_bytes)
    dst_ip = ".".join(str(b) for b in dst_bytes)
    return src_ip, dst_ip


def get_ip_header_length(buf: bytearray, ip_start: int) -> int:
    """Get IP header length in bytes from IHL field."""
    return (buf[ip_start + IP_VERSION_IHL] & 0x0F) * 4


# ============================================================================
# Normalization (for comparison, zeroes volatile fields)
# ============================================================================

def normalize(pkt: bytes) -> bytes:
    """
    Normalize a packet by zeroing volatile fields.
    
    This is used for COMPARING packets across runs, not for transmission.
    Zeroes: IP ID, IP checksum, UDP checksum.
    """
    if len(pkt) < ETH_HEADER_LEN + 20:  # Min Ethernet + IP header
        return pkt

    buf = bytearray(pkt)

    ethertype = struct.unpack("!H", buf[ETH_TYPE:ETH_TYPE + 2])[0]
    if ethertype != ETHERTYPE_IPV4:
        return bytes(buf)

    ip = ETH_HEADER_LEN

    # Zero IP identification
    buf[ip + IP_ID] = 0
    buf[ip + IP_ID + 1] = 0

    # Zero IP header checksum
    buf[ip + IP_CHECKSUM] = 0
    buf[ip + IP_CHECKSUM + 1] = 0

    ihl = get_ip_header_length(buf, ip)
    proto = buf[ip + IP_PROTOCOL]

    # Zero UDP checksum
    if proto == PROTO_UDP and len(buf) >= ip + ihl + UDP_HEADER_LEN:
        udp = ip + ihl
        buf[udp + UDP_CHECKSUM] = 0
        buf[udp + UDP_CHECKSUM + 1] = 0

    return bytes(buf)


def simple_warden(pkts: list[bytes]) -> list[bytes]:
    """Apply normalization to a list of packets."""
    return [normalize(p) for p in pkts]


# ============================================================================
# Active Warden Scrubbing
# ============================================================================

def scrub_packet(
    pkt: bytes,
    rng: "CoinFlipRNG",
    conn_tracker: ConnectionTracker,
    server_ip: str = SERVER_IP,
    client_ip: str = CLIENT_IP,
) -> bytes:
    """
    Scrub a packet to eliminate covert channels while maintaining validity.
    
    This function:
    1. Replaces IP ID with a coin-flip RNG value
    2. Canonicalizes IP TTL to 64
    3. Enforces server source port consistency (via connection tracking)
    4. Recomputes IP and UDP checksums
    
    Args:
        pkt: Raw packet bytes (Ethernet frame)
        rng: CoinFlipRNG instance for random values
        conn_tracker: ConnectionTracker for server port enforcement
        server_ip: Server's IP address
        client_ip: Client's IP address
    
    Returns:
        Scrubbed packet bytes
    """
    # Minimum size check: Ethernet header + minimum IP header
    if len(pkt) < ETH_HEADER_LEN + 20:
        return pkt

    buf = bytearray(pkt)

    # Check EtherType is IPv4
    ethertype = struct.unpack("!H", buf[ETH_TYPE:ETH_TYPE + 2])[0]
    if ethertype != ETHERTYPE_IPV4:
        return bytes(buf)

    ip = ETH_HEADER_LEN
    ihl = get_ip_header_length(buf, ip)
    proto = buf[ip + IP_PROTOCOL]

    # Parse IP addresses
    src_ip, dst_ip = parse_ip_addresses(buf, ip)

    # --- IP Header Scrubbing ---
    
    # 1. Replace IP ID with RNG value (2 bytes)
    new_ip_id = rng.next(size_bytes=2)
    buf[ip + IP_ID] = (new_ip_id >> 8) & 0xFF
    buf[ip + IP_ID + 1] = new_ip_id & 0xFF

    # 2. Canonicalize TTL to 64
    buf[ip + IP_TTL] = CANONICAL_TTL

    # --- UDP-specific Scrubbing ---
    
    if proto == PROTO_UDP and len(buf) >= ip + ihl + UDP_HEADER_LEN:
        udp = ip + ihl
        
        src_port = struct.unpack("!H", buf[udp + UDP_SRC_PORT : udp + UDP_SRC_PORT + 2])[0]
        dst_port = struct.unpack("!H", buf[udp + UDP_DST_PORT : udp + UDP_DST_PORT + 2])[0]
        
        # Determine packet direction
        is_from_client = (src_ip == client_ip)
        is_from_server = (src_ip == server_ip)
        
        # 3. Connection tracking for server source port enforcement
        if is_from_client:
            # Inbound: client -> server
            # Record that responses to this client should come from dst_port
            conn_tracker.record_inbound(src_ip, src_port, dst_port)
        
        elif is_from_server:
            # Outbound: server -> client
            # Enforce that source port matches the expected port
            expected_port = conn_tracker.get_expected_src_port(dst_ip, dst_port)
            if expected_port is not None and src_port != expected_port:
                # Rewrite source port to expected value
                buf[udp + UDP_SRC_PORT] = (expected_port >> 8) & 0xFF
                buf[udp + UDP_SRC_PORT + 1] = expected_port & 0xFF
        
        # 4. Recompute UDP checksum
        # First, zero the checksum field
        buf[udp + UDP_CHECKSUM] = 0
        buf[udp + UDP_CHECKSUM + 1] = 0
        
        # Extract components for checksum calculation
        udp_header = bytes(buf[udp : udp + UDP_HEADER_LEN])
        payload = bytes(buf[udp + UDP_HEADER_LEN :])
        src_ip_bytes = buf[ip + IP_SRC : ip + IP_SRC + 4]
        dst_ip_bytes = buf[ip + IP_DST : ip + IP_DST + 4]
        
        new_udp_checksum = compute_udp_checksum(
            bytes(src_ip_bytes),
            bytes(dst_ip_bytes),
            udp_header,
            payload,
        )
        
        buf[udp + UDP_CHECKSUM] = (new_udp_checksum >> 8) & 0xFF
        buf[udp + UDP_CHECKSUM + 1] = new_udp_checksum & 0xFF

    # 5. Recompute IP header checksum (after all IP header modifications)
    # Zero the checksum field first
    buf[ip + IP_CHECKSUM] = 0
    buf[ip + IP_CHECKSUM + 1] = 0
    
    ip_header = bytes(buf[ip : ip + ihl])
    new_ip_checksum = compute_ip_checksum(ip_header)
    
    buf[ip + IP_CHECKSUM] = (new_ip_checksum >> 8) & 0xFF
    buf[ip + IP_CHECKSUM + 1] = new_ip_checksum & 0xFF

    return bytes(buf)


def scrub_packets(
    pkts: list[bytes],
    rng: "CoinFlipRNG",
    conn_tracker: Optional[ConnectionTracker] = None,
    server_ip: str = SERVER_IP,
    client_ip: str = CLIENT_IP,
) -> list[bytes]:
    """
    Scrub a list of packets.
    
    Args:
        pkts: List of raw packet bytes
        rng: CoinFlipRNG instance
        conn_tracker: ConnectionTracker (created if None)
        server_ip: Server's IP address
        client_ip: Client's IP address
    
    Returns:
        List of scrubbed packets
    """
    if conn_tracker is None:
        conn_tracker = ConnectionTracker()
    
    return [
        scrub_packet(pkt, rng, conn_tracker, server_ip, client_ip)
        for pkt in pkts
    ]


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
