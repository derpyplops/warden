#!/usr/bin/env python3
"""
Tests for the Warden scrubber.

Verifies:
1. Reproducibility: same RNG seeds produce identical scrubbed output
2. Checksum validity: IP and UDP checksums are correct after scrubbing
3. Connection tracking: server source port enforcement works correctly
"""

import struct
import unittest
from typing import Optional

from coin_flip import CoinFlipRNG, generate_seeds
from analyze import (
    scrub_packet,
    scrub_packets,
    ConnectionTracker,
    compute_ip_checksum,
    compute_udp_checksum,
    normalize,
    ETH_HEADER_LEN,
    IP_ID,
    IP_TTL,
    IP_CHECKSUM,
    IP_PROTOCOL,
    IP_SRC,
    IP_DST,
    UDP_SRC_PORT,
    UDP_CHECKSUM,
    UDP_HEADER_LEN,
    CANONICAL_TTL,
    PROTO_UDP,
    SERVER_IP,
    CLIENT_IP,
)


# ============================================================================
# Test Packet Builders
# ============================================================================

def build_test_packet(
    src_ip: str = CLIENT_IP,
    dst_ip: str = SERVER_IP,
    src_port: int = 54321,
    dst_port: int = 5000,
    payload: bytes = b"test payload",
    ip_id: int = 0x1234,
    ttl: int = 128,
) -> bytes:
    """
    Build a minimal valid Ethernet/IPv4/UDP packet for testing.
    """
    # Ethernet header
    dst_mac = bytes.fromhex("02000a000001")
    src_mac = bytes.fromhex("02000a000002")
    ethertype = struct.pack("!H", 0x0800)
    eth_header = dst_mac + src_mac + ethertype
    
    # IP header (20 bytes, no options)
    version_ihl = 0x45
    tos = 0
    total_len = 20 + 8 + len(payload)  # IP + UDP + payload
    flags_frag = 0x4000  # DF bit
    protocol = PROTO_UDP
    
    # Parse IPs
    src_ip_bytes = bytes(int(x) for x in src_ip.split("."))
    dst_ip_bytes = bytes(int(x) for x in dst_ip.split("."))
    
    # Build IP header with checksum = 0 first
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len,
        ip_id, flags_frag,
        ttl, protocol, 0,  # checksum = 0
        src_ip_bytes, dst_ip_bytes,
    )
    
    # Compute and insert IP checksum
    ip_checksum = compute_ip_checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len,
        ip_id, flags_frag,
        ttl, protocol, ip_checksum,
        src_ip_bytes, dst_ip_bytes,
    )
    
    # UDP header
    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    
    # Compute UDP checksum
    udp_checksum = compute_udp_checksum(src_ip_bytes, dst_ip_bytes, udp_header, payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_checksum)
    
    return eth_header + ip_header + udp_header + payload


def verify_ip_checksum(pkt: bytes) -> bool:
    """Verify the IP header checksum is correct."""
    if len(pkt) < ETH_HEADER_LEN + 20:
        return False
    
    ip = ETH_HEADER_LEN
    ihl = (pkt[ip] & 0x0F) * 4
    ip_header = bytearray(pkt[ip : ip + ihl])
    
    # Store original checksum
    original = struct.unpack("!H", ip_header[IP_CHECKSUM : IP_CHECKSUM + 2])[0]
    
    # Zero checksum field and recompute
    ip_header[IP_CHECKSUM] = 0
    ip_header[IP_CHECKSUM + 1] = 0
    computed = compute_ip_checksum(bytes(ip_header))
    
    return original == computed


def verify_udp_checksum(pkt: bytes) -> bool:
    """Verify the UDP checksum is correct."""
    if len(pkt) < ETH_HEADER_LEN + 20 + UDP_HEADER_LEN:
        return False
    
    ip = ETH_HEADER_LEN
    ihl = (pkt[ip] & 0x0F) * 4
    proto = pkt[ip + IP_PROTOCOL]
    
    if proto != PROTO_UDP:
        return False
    
    udp = ip + ihl
    udp_header = bytearray(pkt[udp : udp + UDP_HEADER_LEN])
    payload = pkt[udp + UDP_HEADER_LEN :]
    
    # Store original checksum
    original = struct.unpack("!H", udp_header[UDP_CHECKSUM : UDP_CHECKSUM + 2])[0]
    
    # Zero checksum field and recompute
    udp_header[UDP_CHECKSUM] = 0
    udp_header[UDP_CHECKSUM + 1] = 0
    
    src_ip_bytes = pkt[ip + IP_SRC : ip + IP_SRC + 4]
    dst_ip_bytes = pkt[ip + IP_DST : ip + IP_DST + 4]
    
    computed = compute_udp_checksum(src_ip_bytes, dst_ip_bytes, bytes(udp_header), payload)
    
    return original == computed


# ============================================================================
# Test Cases
# ============================================================================

class TestReproducibility(unittest.TestCase):
    """Test that scrubbing with the same RNG seeds produces identical output."""
    
    def test_same_seeds_same_output(self):
        """Two RNGs with identical seeds should produce identical scrubbed packets."""
        # Create seeds
        prover_seeds = generate_seeds(n=100, size_bytes=4)
        verifier_seeds = generate_seeds(n=100, size_bytes=4)
        
        # Create two RNGs with same seeds
        rng1 = CoinFlipRNG(n_values=100, prover_seeds=prover_seeds, verifier_seeds=verifier_seeds)
        rng2 = CoinFlipRNG(n_values=100, prover_seeds=prover_seeds, verifier_seeds=verifier_seeds)
        
        # Create test packets
        packets = [
            build_test_packet(payload=f"packet {i}".encode())
            for i in range(10)
        ]
        
        # Scrub with both RNGs
        tracker1 = ConnectionTracker()
        tracker2 = ConnectionTracker()
        
        scrubbed1 = [scrub_packet(p, rng1, tracker1) for p in packets]
        scrubbed2 = [scrub_packet(p, rng2, tracker2) for p in packets]
        
        # Verify identical output
        for i, (s1, s2) in enumerate(zip(scrubbed1, scrubbed2)):
            self.assertEqual(s1, s2, f"Packet {i} differs")
    
    def test_different_seeds_different_output(self):
        """Two RNGs with different seeds should produce different scrubbed packets."""
        rng1 = CoinFlipRNG(n_values=100, size_bytes=4)
        rng2 = CoinFlipRNG(n_values=100, size_bytes=4)
        
        packet = build_test_packet()
        
        tracker1 = ConnectionTracker()
        tracker2 = ConnectionTracker()
        
        scrubbed1 = scrub_packet(packet, rng1, tracker1)
        scrubbed2 = scrub_packet(packet, rng2, tracker2)
        
        # Should differ (at least in IP ID)
        self.assertNotEqual(scrubbed1, scrubbed2)


class TestChecksumValidity(unittest.TestCase):
    """Test that scrubbed packets have valid checksums."""
    
    def test_ip_checksum_valid_after_scrub(self):
        """IP header checksum should be valid after scrubbing."""
        rng = CoinFlipRNG(n_values=100, size_bytes=4)
        tracker = ConnectionTracker()
        
        packets = [
            build_test_packet(payload=f"test {i}".encode(), ttl=100 + i)
            for i in range(5)
        ]
        
        for i, pkt in enumerate(packets):
            scrubbed = scrub_packet(pkt, rng, tracker)
            self.assertTrue(
                verify_ip_checksum(scrubbed),
                f"Packet {i} has invalid IP checksum after scrubbing"
            )
    
    def test_udp_checksum_valid_after_scrub(self):
        """UDP checksum should be valid after scrubbing."""
        rng = CoinFlipRNG(n_values=100, size_bytes=4)
        tracker = ConnectionTracker()
        
        packets = [
            build_test_packet(payload=f"payload number {i}".encode())
            for i in range(5)
        ]
        
        for i, pkt in enumerate(packets):
            scrubbed = scrub_packet(pkt, rng, tracker)
            self.assertTrue(
                verify_udp_checksum(scrubbed),
                f"Packet {i} has invalid UDP checksum after scrubbing"
            )
    
    def test_checksums_valid_with_various_payloads(self):
        """Checksums should be valid for various payload sizes."""
        rng = CoinFlipRNG(n_values=100, size_bytes=4)
        tracker = ConnectionTracker()
        
        # Test various payload sizes including odd lengths
        for payload_size in [0, 1, 2, 7, 100, 1000]:
            payload = b"X" * payload_size
            pkt = build_test_packet(payload=payload)
            scrubbed = scrub_packet(pkt, rng, tracker)
            
            self.assertTrue(
                verify_ip_checksum(scrubbed),
                f"Invalid IP checksum for payload size {payload_size}"
            )
            self.assertTrue(
                verify_udp_checksum(scrubbed),
                f"Invalid UDP checksum for payload size {payload_size}"
            )


class TestTTLCanonicalization(unittest.TestCase):
    """Test that TTL is correctly canonicalized."""
    
    def test_ttl_set_to_canonical_value(self):
        """TTL should be set to CANONICAL_TTL (64) after scrubbing."""
        rng = CoinFlipRNG(n_values=100, size_bytes=4)
        tracker = ConnectionTracker()
        
        # Test various initial TTL values
        for initial_ttl in [1, 32, 64, 128, 255]:
            pkt = build_test_packet(ttl=initial_ttl)
            scrubbed = scrub_packet(pkt, rng, tracker)
            
            # Check TTL in scrubbed packet
            ip = ETH_HEADER_LEN
            actual_ttl = scrubbed[ip + IP_TTL]
            
            self.assertEqual(
                actual_ttl, CANONICAL_TTL,
                f"TTL not canonicalized from {initial_ttl}"
            )


class TestIPIDReplacement(unittest.TestCase):
    """Test that IP ID is replaced with RNG values."""
    
    def test_ip_id_replaced(self):
        """IP ID should be replaced, not preserved."""
        prover_seeds = generate_seeds(n=100, size_bytes=4)
        verifier_seeds = generate_seeds(n=100, size_bytes=4)
        rng = CoinFlipRNG(n_values=100, prover_seeds=prover_seeds, verifier_seeds=verifier_seeds)
        tracker = ConnectionTracker()
        
        original_ip_id = 0xABCD
        pkt = build_test_packet(ip_id=original_ip_id)
        scrubbed = scrub_packet(pkt, rng, tracker)
        
        # Extract IP ID from scrubbed packet
        ip = ETH_HEADER_LEN
        scrubbed_ip_id = struct.unpack("!H", scrubbed[ip + IP_ID : ip + IP_ID + 2])[0]
        
        # Should be different (unless extremely unlucky RNG)
        # We can't assert exact value without knowing RNG output,
        # but we can check it's different from original
        # Actually, let's verify it matches RNG output
        
        # Reset and get expected value
        rng.reset()
        expected_ip_id = rng.next(size_bytes=2)
        
        self.assertEqual(scrubbed_ip_id, expected_ip_id)


class TestConnectionTracking(unittest.TestCase):
    """Test connection tracking for server source port enforcement."""
    
    def test_server_port_enforced(self):
        """Server source port should be enforced to match the request destination."""
        rng = CoinFlipRNG(n_values=100, size_bytes=4)
        tracker = ConnectionTracker()
        
        # Client sends request to server port 5000
        client_request = build_test_packet(
            src_ip=CLIENT_IP,
            dst_ip=SERVER_IP,
            src_port=54321,
            dst_port=5000,
            payload=b"request",
        )
        
        # Server tries to respond from port 5001 (steganography attempt)
        server_response = build_test_packet(
            src_ip=SERVER_IP,
            dst_ip=CLIENT_IP,
            src_port=5001,  # Wrong port!
            dst_port=54321,
            payload=b"response",
        )
        
        # Scrub the request (records the connection)
        scrub_packet(client_request, rng, tracker)
        
        # Scrub the response (should fix the port)
        scrubbed_response = scrub_packet(server_response, rng, tracker)
        
        # Extract source port from scrubbed response
        ip = ETH_HEADER_LEN
        ihl = (scrubbed_response[ip] & 0x0F) * 4
        udp = ip + ihl
        scrubbed_src_port = struct.unpack(
            "!H", scrubbed_response[udp + UDP_SRC_PORT : udp + UDP_SRC_PORT + 2]
        )[0]
        
        # Should be corrected to 5000
        self.assertEqual(scrubbed_src_port, 5000)
    
    def test_legitimate_port_preserved(self):
        """Legitimate server source port should not be changed."""
        rng = CoinFlipRNG(n_values=100, size_bytes=4)
        tracker = ConnectionTracker()
        
        # Client sends request to server port 5000
        client_request = build_test_packet(
            src_ip=CLIENT_IP,
            dst_ip=SERVER_IP,
            src_port=54321,
            dst_port=5000,
            payload=b"request",
        )
        
        # Server responds correctly from port 5000
        server_response = build_test_packet(
            src_ip=SERVER_IP,
            dst_ip=CLIENT_IP,
            src_port=5000,  # Correct port
            dst_port=54321,
            payload=b"response",
        )
        
        # Scrub both
        scrub_packet(client_request, rng, tracker)
        scrubbed_response = scrub_packet(server_response, rng, tracker)
        
        # Extract source port
        ip = ETH_HEADER_LEN
        ihl = (scrubbed_response[ip] & 0x0F) * 4
        udp = ip + ihl
        scrubbed_src_port = struct.unpack(
            "!H", scrubbed_response[udp + UDP_SRC_PORT : udp + UDP_SRC_PORT + 2]
        )[0]
        
        # Should still be 5000
        self.assertEqual(scrubbed_src_port, 5000)
    
    def test_connection_expiry(self):
        """Expired connections should not enforce port."""
        tracker = ConnectionTracker(timeout_seconds=0.01)  # Very short timeout
        
        # Record a connection
        tracker.record_inbound(CLIENT_IP, 54321, 5000)
        
        # Wait for expiry
        import time
        time.sleep(0.02)
        
        # Should return None (expired)
        expected = tracker.get_expected_src_port(CLIENT_IP, 54321)
        self.assertIsNone(expected)


class TestCoinFlipRNG(unittest.TestCase):
    """Test the CoinFlipRNG class itself."""
    
    def test_pool_exhaustion(self):
        """Should raise when pool is exhausted."""
        rng = CoinFlipRNG(n_values=5, size_bytes=4)
        
        # Draw all values
        for _ in range(5):
            rng.next()
        
        # Next draw should fail
        with self.assertRaises(RuntimeError):
            rng.next()
    
    def test_remaining_count(self):
        """Remaining count should decrease correctly."""
        rng = CoinFlipRNG(n_values=10, size_bytes=4)
        
        self.assertEqual(rng.remaining, 10)
        rng.next()
        self.assertEqual(rng.remaining, 9)
        rng.next()
        rng.next()
        self.assertEqual(rng.remaining, 7)
    
    def test_size_truncation(self):
        """Values should be truncated to requested size."""
        rng = CoinFlipRNG(n_values=10, size_bytes=4)
        
        # Request 2 bytes from 4-byte pool
        value = rng.next(size_bytes=2)
        
        # Should fit in 2 bytes
        self.assertLessEqual(value, 0xFFFF)
    
    def test_reset(self):
        """Reset should allow reusing values."""
        prover_seeds = generate_seeds(n=10, size_bytes=4)
        verifier_seeds = generate_seeds(n=10, size_bytes=4)
        rng = CoinFlipRNG(n_values=10, prover_seeds=prover_seeds, verifier_seeds=verifier_seeds)
        
        # Draw some values
        first_values = [rng.next() for _ in range(5)]
        
        # Reset
        rng.reset()
        
        # Should get same values
        second_values = [rng.next() for _ in range(5)]
        
        self.assertEqual(first_values, second_values)


if __name__ == "__main__":
    unittest.main()
