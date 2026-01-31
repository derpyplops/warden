# Network Tap Protocol Scrubbing for AI Compute Verification

## Context: AI Safety and Comprehensive Verification

As AI systems become increasingly powerful, international agreements and treaties will likely require verification that datacenters comply with compute usage restrictions. Most verification research focuses on **compliance** - ensuring declared workloads meet regulations (e.g., no training on copyrighted data, no bioweapon-related inference). 

This project addresses a distinct problem: **comprehensiveness** - verifying that a datacenter operator (the "Prover") has declared *all* computational workloads, with no hidden, undeclared compute usage. The goal is to ensure nothing is concealed, rather than determining whether declared activities are permitted.

### Verification Pipeline

Our work targets Level 2 in the verification pipeline:

1. **Physical monitoring** - Ensure no covert communication devices (out of scope)
2. **Evidence capture** - Hash and timestamp all network traffic (our focus)
3. **Replay verification** - Confirm declared workloads match captured hashes (out of scope)
4. **Compliance evaluation** - Assess legal adherence of verified workloads (out of scope)

### The Core Challenge

If a Verifier (regulatory agency, treaty member, government) can capture cryptographic hashes and timestamps of all traffic entering/leaving a datacenter, and the Prover can later demonstrate their declared workloads correspond to these hashes, the Verifier gains confidence that no undeclared computation occurred.

This raises critical questions:

1. **Completeness**: How can the Verifier ensure they capture *all* ingress/egress traffic?
2. **Steganography**: How can we prevent the Prover from hiding information in monitored traffic through steganographic techniques, side-channels, or timing attacks?
3. **Reproducibility**: How can the Prover demonstrate their workload matches captured hashes when protocol metadata contains ephemeral random values?
4. **Security**: How do we maintain protocol security properties (e.g., protection against sequence prediction attacks) while eliminating steganographic channels?

## Active Warden Framework

### Background: Fisk et al. (2002)

The foundational work by Fisk et al. on "Active Wardens" addresses steganography in network traffic. Key concepts:

**Minimal Requisite Fidelity (MRF)**: The minimum signal fidelity that preserves legitimate communication while destroying covert channels. For structured carriers (protocols with well-defined semantics like TCP/IP), MRF can be precisely determined from specifications, unlike unstructured carriers (images, audio) where human perception limits distortion.

**Protocol Scrubbing**: Network protocols contain numerous ambiguous fields - padding bits, unused options, marginally-significant values - that create steganographic opportunities. An active warden normalises these to canonical forms:

- Zero padding bits
- Zero unused/reserved fields  
- Canonicalise IP identification numbers
- Normalise TCP sequence number offsets
- Remove ambiguous options

### Adaptation for Mutual Distrust

The original active warden assumes a trusted party controlling the warden. Our scenario involves two mutually distrusting parties:

- **Prover** (datacenter operator) - Must not control randomness used in protocol scrubbing
- **Verifier** (regulatory agency) - Must not be able to manipulate evidence capture

Our contribution extends the active warden concept to operate under mutual distrust through:

1. **Passive observability** - Hashes and timestamps sent to the Verifier can be observed by the Prover (one-way channel), confirming correct computation
2. **Joint randomness generation** - Cryptographic coin-flip protocol between Prover-trusted and Verifier-trusted devices ensures neither party controls random values used in scrubbing

## Protocol Scrubbing Requirements

### What Must Be Scrubbed

Network protocol headers contain information that serves two conflicting purposes:

1. **Legitimate protocol operation** - Sequence numbers, checksums, flags
2. **Steganographic channels** - Any field the Prover can control encodes information

Fields requiring scrubbing include:

- **TCP Initial Sequence Numbers (ISNs)** - 32-bit random value, ~8 bytes of covert capacity per connection
- **IP Identification fields** - Used for fragment reassembly, often randomised  
- **TCP/UDP source ports** - Quasi-random for client connections
- **Padding bits** - Unused space in headers and payloads
- **TCP options** - Variable fields with loose semantics
- **Reserved/unused fields** - Future-proofing space in protocol design

At 500M packets/day with ~8 bytes per packet of covert capacity, an insider could exfiltrate 26GB annually through timing control alone, or 4GB daily with full packet control.

### The Zeroing vs. Re-randomisation Dilemma

**Why not simply zero all random fields?**

Initial intuition suggests replacing all random protocol values (ISNs, IP IDs, etc.) with zeros or fixed constants. This would be:

- **Deterministic** - Prover knows exactly what transformation was applied
- **Reproducible** - When replaying workloads, apply identical zeroing to match hashes  
- **Simple** - No additional cryptographic protocols required

However, this approach creates a critical security vulnerability.

### Security Impact of Zeroed Random Numbers

TCP Initial Sequence Numbers are random for essential security reasons:

**Sequence Prediction Attacks**: If ISNs are predictable (including always zero), an external attacker can:

1. Observe the datacenter initiates connections with ISN = 0
2. Forge packets with predictable sequence numbers
3. Inject data into legitimate TCP streams or reset connections

**Blind In-Window Attacks** (RFC 6528): Even without observing traffic, an attacker knowing ISN = 0 can:

1. Calculate the approximate TCP window range
2. Flood with packets spanning likely sequence numbers  
3. Successfully inject or disrupt connections

**Real-world implications**:

- External attackers could DoS datacenter connections, disrupting training jobs
- Malicious external services could inject poisoned data that gets hashed into evidence
- Attackers could create ambiguity about what computation actually occurred
- This could be used to frame the Prover or undermine verification integrity

### The Asymmetric Threat Model

The challenge arises from asymmetric threats:

- **Outbound (datacenter → internet)**: Prover-controlled randomness enables steganography  
- **Inbound (internet → datacenter)**: Predictable values enable external attacks

Zeroing satisfies the steganography requirement but violates the security requirement.

## Coin-Flip RNG Solution

### Cryptographic Commitment Protocol

The solution employs a joint random number generation protocol between two hardware devices:

- **Prover's device** - Trusted by datacenter operator
- **Verifier's device** - Trusted by regulatory agency

**Protocol flow**:

1. Both devices generate random values (R_p, R_v) independently
2. Both compute cryptographic commitments (hash + timestamp + signature)
3. Both reveal their values with temporal separation (critical: no simultaneous transmission)
4. Final value: R_final = R_p ⊕ R_v (XOR or similar combination)

**Security properties**:

- **Temporal separation**: Sequential revelation prevents either party manipulating outcomes based on the other's value
- **Commitment binding**: Cryptographic hashes prevent changing values post-commitment  
- **Unpredictability**: Neither party controls the final random value
- **Verifiability**: Both parties can confirm correct protocol execution

### Why This Solves Both Problems

**Eliminates steganography** (Prover → outside world):
- Prover cannot control ISNs or other random protocol fields
- All randomness derives from joint, verifiable process
- Steganographic channel capacity reduced to zero for these fields

**Maintains security** (outside world → datacenter):
- External servers receive genuinely random, unpredictable ISNs
- Protection against sequence prediction attacks preserved
- RFC 6528 security requirements satisfied

**Enables verification** (Prover → Verifier):
- Prover can query "what random value was used for connection X at time T?"
- When replaying workloads, Prover applies identical transformations
- Hash reproducibility maintained despite dynamic protocol values

### Implementation Architecture

The network tap operates as a **passive tap with active warden functionality**:

**Passive tap**: 
- Observes traffic without interference (optical splitter on fiber links)
- Minimal latency impact on datacenter operations
- One-way visibility: Verifier observes hashes, Prover observes hash computation

**Active warden functionality**:
- Protocol scrubbing module parses and modifies packet headers
- RNG via coin-flip protocol replaces Prover-controlled random fields
- Bidirectional translation maintains TCP connection state (similar to NAT)

**Warden device components**:

```
┌─────────────────────────────────────────────────┐
│              Warden Device                      │
│                                                 │
│  ┌──────────┐     ┌─────────────────────┐     │
│  │ Passive  │────▶│ Protocol Scrubber   │     │
│  │   Tap    │     │  - Parse headers    │     │
│  └──────────┘     │  - Apply MRF rules  │     │
│                   │  - Replace random   │     │
│                   │    fields with      │     │
│  ┌──────────┐    │    coin-flip RNG    │     │
│  │ Prover's │    │  - Recompute        │     │
│  │  Device  │───▶│    checksums        │     │
│  └──────────┘    └──────┬──────────────┘     │
│                          │                     │
│  ┌──────────┐           │  ┌────────────────┐ │
│  │Verifier's│───────────┼─▶│ Hash & Time-   │ │
│  │  Device  │           │  │ stamp Processor│ │
│  └──────────┘           │  └────────┬───────┘ │
│                         │           │          │
│                         ▼           ▼          │
│                 Modified packet  Evidence      │
│                      egress      to Verifier   │
└─────────────────────────────────────────────────┘
```

### Connection State Management

Replacing ISNs requires maintaining bidirectional translation state (analogous to NAT):

**Outbound (datacenter → internet)**:
- Original packet: ISN_cluster
- Scrubbed packet: ISN_warden (from coin-flip)
- External server responds acknowledging ISN_warden + 1

**Inbound (internet → datacenter)**:  
- Server acknowledgment: ACK = ISN_warden + 1
- Translated for cluster: ACK = ISN_cluster + 1
- Connection state persists for session lifetime

This translation is transparent to both endpoints while maintaining TCP semantics.

## Current Implementation Status

The repository simulates deterministic packet transmission for testing reproducibility:

- **Server**: Precomputes Ethernet frames from JSON payloads, sends via raw sockets
- **Client**: Triggers transmission, receives packets  
- **Analyzer**: Compares packet streams to detect differences
- **Network namespaces**: Isolated testing environment (veth pair)

### Next Steps

1. **Protocol parser implementation**: Parse Ethernet/IP/UDP/TCP headers at wire level
2. **MRF rule engine**: Apply Fisk et al. scrubbing rules to identified protocol fields
3. **Coin-flip protocol**: Implement cryptographic commitment scheme for joint RNG
4. **Connection state tracking**: Maintain translation tables for TCP connections
5. **Hash and timestamp generation**: Compute cryptographic hashes of scrubbed packets
6. **Passive observability**: One-way evidence channel to Verifier with Prover visibility

### Testing Approach

The current reproducibility tests validate:

- Deterministic frame generation from identical inputs
- Detection of tampered packets (single-byte modification)
- Isolation via network namespaces

Future tests must validate:

- Correct MRF scrubbing across protocol variations
- Coin-flip RNG produces uniform, unpredictable values
- Connection state translation preserves TCP semantics
- Hash reproducibility when Prover replays workloads
- Steganographic channel capacity reduction to zero

## References

- **Fisk et al. (2002)**: "Eliminating Steganography in Internet Traffic with Active Wardens"
- **RFC 6528**: "Defending against Sequence Number Attacks"  
- **RFC 6864**: "Updated Specification of the IPv4 ID Field"

## Threat Model Summary

**In scope**:
- Prover attempting steganographic communication through protocol metadata
- External attackers exploiting predictable protocol values
- Verification of comprehensive compute usage via traffic analysis

**Out of scope**:
- Physical security of datacenter and verification facility
- Replay verification logic (Level 3)
- Compliance evaluation of workloads (Level 4)
- Payload-level steganography (requires separate analysis)

## Key Design Principles

1. **Mutual distrust**: Neither Prover nor Verifier can unilaterally control evidence
2. **Passive observability**: All parties can verify correct operation without trust
3. **Minimal disruption**: Network tap preserves datacenter performance and latency
4. **Deterministic reproducibility**: Prover can demonstrate workload-to-hash correspondence
5. **Security preservation**: External-facing connections maintain TCP/IP security properties
