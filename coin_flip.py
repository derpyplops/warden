#!/usr/bin/env python3
"""
Coin Flip Protocol for Mutual RNG

Simulates the random number generation process between a Prover's device
and a Verifier's device. Neither party can control or predict the final
random values, which will be used for protocol headers (ISN, IP ID, TLS nonces).
"""

import hashlib
import secrets


def generate_seeds(n=100, size_bytes=4):
    """Generate n random seeds. 4 bytes = 32 bits = ISN size."""
    return [secrets.token_bytes(size_bytes) for _ in range(n)]


def commit(seed_list):
    """Commit to entire list by hashing concatenation of all seeds."""
    return hashlib.sha256(b''.join(seed_list)).digest()


def verify(seed_list, commitment):
    """Verify a revealed seed list matches its commitment."""
    return commit(seed_list) == commitment


def combine(prover_seeds, verifier_seeds):
    """XOR corresponding entries to produce final random values."""
    return [
        int.from_bytes(bytes(a ^ b for a, b in zip(p, v)), 'big')
        for p, v in zip(prover_seeds, verifier_seeds)
    ]


def main():
    print("=" * 60)
    print("COIN FLIP PROTOCOL - Mutual RNG Simulation")
    print("=" * 60)
    
    # === Setup ===
    print("\n[1] SEED GENERATION")
    print("-" * 40)
    
    prover_seeds = generate_seeds()
    verifier_seeds = generate_seeds()
    
    print(f"    Prover generated {len(prover_seeds)} seeds (32-bit each)")
    print(f"    Verifier generated {len(verifier_seeds)} seeds (32-bit each)")
    
    # Show first few raw seeds
    print("\n    Prover's first 3 seeds (hex):")
    for i in range(3):
        print(f"      [{i}] {prover_seeds[i].hex()}")
    
    print("\n    Verifier's first 3 seeds (hex):")
    for i in range(3):
        print(f"      [{i}] {verifier_seeds[i].hex()}")
    
    # === Phase 1: Commitment ===
    print("\n[2] COMMITMENT PHASE")
    print("-" * 40)
    
    prover_commit = commit(prover_seeds)
    verifier_commit = commit(verifier_seeds)
    
    print(f"    Prover commits:  {prover_commit.hex()[:32]}...")
    print(f"    Verifier commits: {verifier_commit.hex()[:32]}...")
    print("\n    (Commitments exchanged - neither can change seeds now)")
    
    # === Phase 2: Reveal ===
    print("\n[3] REVEAL PHASE")
    print("-" * 40)
    print("    Both parties reveal their seed lists...")
    
    # === Phase 3: Verify ===
    print("\n[4] VERIFICATION PHASE")
    print("-" * 40)
    
    prover_valid = verify(prover_seeds, prover_commit)
    verifier_valid = verify(verifier_seeds, verifier_commit)
    
    print(f"    Prover's seeds match commitment:   {prover_valid}")
    print(f"    Verifier's seeds match commitment: {verifier_valid}")
    
    if not (prover_valid and verifier_valid):
        print("\n    ERROR: Commitment mismatch - protocol aborted!")
        return
    
    # === Phase 4: Combine ===
    print("\n[5] COMBINATION PHASE (XOR)")
    print("-" * 40)
    
    final_values = combine(prover_seeds, verifier_seeds)
    
    print("    Computing: final[i] = prover_seed[i] XOR verifier_seed[i]")
    print("\n    Example for index 0:")
    print(f"      Prover:   {prover_seeds[0].hex()} = {int.from_bytes(prover_seeds[0], 'big'):>10}")
    print(f"      Verifier: {verifier_seeds[0].hex()} = {int.from_bytes(verifier_seeds[0], 'big'):>10}")
    print(f"      XOR:      {final_values[0]:08x} = {final_values[0]:>10}")
    
    # === Output ===
    print("\n[6] FINAL OUTPUT - Shared Random ISN Values")
    print("-" * 40)
    print("    Index      Decimal          Hex")
    print("    " + "-" * 36)
    
    for i in range(15):
        print(f"    [{i:3}]  {final_values[i]:>12}    0x{final_values[i]:08x}")
    
    print("    ...")
    print(f"    [{99:3}]  {final_values[99]:>12}    0x{final_values[99]:08x}")
    
    # Stats
    print("\n[7] STATISTICS")
    print("-" * 40)
    print(f"    Total values generated: {len(final_values)}")
    print(f"    Min value: {min(final_values):>12} (0x{min(final_values):08x})")
    print(f"    Max value: {max(final_values):>12} (0x{max(final_values):08x})")
    print(f"    Range:     0 to {2**32 - 1} (full 32-bit)")
    
    print("\n" + "=" * 60)
    print("Protocol complete. Neither party could predict or control")
    print("the final values without the other's cooperation.")
    print("=" * 60)


if __name__ == "__main__":
    main()
