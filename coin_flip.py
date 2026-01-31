#!/usr/bin/env python3
"""
Coin Flip Protocol for Mutual RNG

Simulates the random number generation process between a Prover's device
and a Verifier's device. Neither party can control or predict the final
random values, which will be used for protocol headers (ISN, IP ID, TLS nonces).
"""

import hashlib
import secrets
from typing import Optional


def generate_seeds(n: int = 100, size_bytes: int = 4) -> list[bytes]:
    """Generate n random seeds. 4 bytes = 32 bits = ISN size."""
    return [secrets.token_bytes(size_bytes) for _ in range(n)]


def commit(seed_list: list[bytes]) -> bytes:
    """Commit to entire list by hashing concatenation of all seeds."""
    return hashlib.sha256(b''.join(seed_list)).digest()


def verify(seed_list: list[bytes], commitment: bytes) -> bool:
    """Verify a revealed seed list matches its commitment."""
    return commit(seed_list) == commitment


def combine(prover_seeds: list[bytes], verifier_seeds: list[bytes]) -> list[bytes]:
    """XOR corresponding entries to produce final random values (as bytes)."""
    return [
        bytes(a ^ b for a, b in zip(p, v))
        for p, v in zip(prover_seeds, verifier_seeds)
    ]


class CoinFlipRNG:
    """
    Pre-generated pool of random values from the coin-flip protocol.
    
    In a real deployment, the commit-reveal protocol has network latency
    between Prover and Verifier devices. Pre-generating a pool of values
    allows the warden to operate at line rate without waiting for protocol
    round-trips on every packet.
    
    The pool should be regenerated before exhaustion. A pool of 10,000
    values is a reasonable trade-off: negligible memory (~40KB for 4-byte
    values) but enough to process many packets between regeneration rounds.
    """
    
    def __init__(
        self,
        n_values: int = 10000,
        size_bytes: int = 4,
        prover_seeds: Optional[list[bytes]] = None,
        verifier_seeds: Optional[list[bytes]] = None,
    ):
        """
        Initialize the RNG pool.
        
        Args:
            n_values: Number of random values to pre-generate
            size_bytes: Size of each value in bytes (e.g., 2 for IP ID, 4 for ISN)
            prover_seeds: Optional pre-set seeds (for reproducible testing)
            verifier_seeds: Optional pre-set seeds (for reproducible testing)
        """
        self.size_bytes = size_bytes
        self.n_values = n_values
        
        # Generate or use provided seeds
        if prover_seeds is None:
            prover_seeds = generate_seeds(n_values, size_bytes)
        if verifier_seeds is None:
            verifier_seeds = generate_seeds(n_values, size_bytes)
        
        # Store commitments (in real protocol, these would be exchanged)
        self.prover_commitment = commit(prover_seeds)
        self.verifier_commitment = commit(verifier_seeds)
        
        # Verify commitments match revealed seeds
        if not verify(prover_seeds, self.prover_commitment):
            raise ValueError("Prover commitment verification failed")
        if not verify(verifier_seeds, self.verifier_commitment):
            raise ValueError("Verifier commitment verification failed")
        
        # Combine to produce final values
        self._pool = combine(prover_seeds, verifier_seeds)
        self._index = 0
    
    def next(self, size_bytes: Optional[int] = None) -> int:
        """
        Get the next random value from the pool.
        
        Args:
            size_bytes: If specified, truncate/mask to this many bytes.
                        If None, uses the pool's default size.
        
        Returns:
            Random integer value
        
        Raises:
            RuntimeError: If pool is exhausted
        """
        if self._index >= len(self._pool):
            raise RuntimeError(
                f"RNG pool exhausted after {self._index} values. "
                "Regenerate pool with a new coin-flip round."
            )
        
        value_bytes = self._pool[self._index]
        self._index += 1
        
        # Convert to integer
        value = int.from_bytes(value_bytes, 'big')
        
        # Truncate if requested size is smaller than pool's size
        if size_bytes is not None and size_bytes < self.size_bytes:
            mask = (1 << (size_bytes * 8)) - 1
            value = value & mask
        
        return value
    
    def next_bytes(self, size_bytes: Optional[int] = None) -> bytes:
        """
        Get the next random value as bytes.
        
        Args:
            size_bytes: Number of bytes to return. If None, uses pool's default.
        
        Returns:
            Random bytes
        """
        if size_bytes is None:
            size_bytes = self.size_bytes
        
        value = self.next(size_bytes)
        return value.to_bytes(size_bytes, 'big')
    
    @property
    def remaining(self) -> int:
        """Number of values remaining in the pool."""
        return len(self._pool) - self._index
    
    def reset(self) -> None:
        """Reset the pool index to reuse values (for testing only)."""
        self._index = 0


def main():
    print("=" * 60)
    print("COIN FLIP PROTOCOL - Mutual RNG Simulation")
    print("=" * 60)
    
    # === Demo of low-level functions ===
    print("\n[1] LOW-LEVEL PROTOCOL DEMO")
    print("-" * 40)
    
    prover_seeds = generate_seeds(n=10, size_bytes=4)
    verifier_seeds = generate_seeds(n=10, size_bytes=4)
    
    print(f"    Prover generated {len(prover_seeds)} seeds (32-bit each)")
    print(f"    Verifier generated {len(verifier_seeds)} seeds (32-bit each)")
    
    prover_commit = commit(prover_seeds)
    verifier_commit = commit(verifier_seeds)
    
    print(f"    Prover commits:  {prover_commit.hex()[:32]}...")
    print(f"    Verifier commits: {verifier_commit.hex()[:32]}...")
    
    final_values = combine(prover_seeds, verifier_seeds)
    
    print("\n    Combined values (XOR):")
    for i in range(5):
        val = int.from_bytes(final_values[i], 'big')
        print(f"      [{i}] {final_values[i].hex()} = {val}")
    
    # === Demo of CoinFlipRNG class ===
    print("\n" + "=" * 60)
    print("[2] CoinFlipRNG CLASS DEMO")
    print("-" * 40)
    
    # Create RNG pool with 10,000 values
    rng = CoinFlipRNG(n_values=10000, size_bytes=4)
    
    print(f"    Pool size: {rng.n_values} values")
    print(f"    Value size: {rng.size_bytes} bytes")
    print(f"    Remaining: {rng.remaining}")
    
    print("\n    Drawing values from pool:")
    for i in range(5):
        val = rng.next()
        print(f"      [{i}] 0x{val:08x} ({val})")
    
    print(f"\n    Remaining after 5 draws: {rng.remaining}")
    
    # Demo of truncation for IP ID (2 bytes)
    print("\n    Drawing 2-byte values (for IP ID):")
    for i in range(3):
        val = rng.next(size_bytes=2)
        print(f"      [{i}] 0x{val:04x} ({val})")
    
    # Demo of reproducibility
    print("\n" + "=" * 60)
    print("[3] REPRODUCIBILITY DEMO")
    print("-" * 40)
    
    # Create two RNGs with same seeds
    seed_p = generate_seeds(n=100, size_bytes=4)
    seed_v = generate_seeds(n=100, size_bytes=4)
    
    rng1 = CoinFlipRNG(n_values=100, prover_seeds=seed_p, verifier_seeds=seed_v)
    rng2 = CoinFlipRNG(n_values=100, prover_seeds=seed_p, verifier_seeds=seed_v)
    
    print("    Two RNGs created with identical seeds:")
    match = True
    for i in range(5):
        v1 = rng1.next()
        v2 = rng2.next()
        status = "==" if v1 == v2 else "!="
        if v1 != v2:
            match = False
        print(f"      RNG1: 0x{v1:08x}  {status}  RNG2: 0x{v2:08x}")
    
    print(f"\n    Reproducible: {match}")
    
    print("\n" + "=" * 60)
    print("Protocol complete. The CoinFlipRNG class provides a")
    print("pre-generated pool for high-throughput packet scrubbing.")
    print("=" * 60)


if __name__ == "__main__":
    main()
