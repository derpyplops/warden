# Warden

A deterministic network packet transmission and analysis system for testing reproducibility and integrity of Ethernet frame delivery.

## Overview

Warden is a server-client system that:

- Precomputes deterministic Ethernet frames from JSON payloads
- Sends frames via raw sockets in isolated network namespaces
- Captures and analyzes packet streams to verify reproducibility
- Detects tampering or modifications to transmitted data

## Components

- **server.py** - Precomputes Ethernet frames and sends them on UDP trigger
- **client.py** - Sends trigger and receives response packets
- **analyze.py** - Compares captured packet streams for differences
- **run.sh** - Integration test script with network namespace setup
- **Dockerfile** - Container environment for isolated testing

## Architecture

The system uses Linux network namespaces to create isolated server and client environments connected by a virtual ethernet pair (`veth`). This allows controlled testing of packet transmission without external network interference.

### Network Setup

```
┌─────────────────────┐      ┌─────────────────────┐
│   ns_server         │      │   ns_client         │
│  10.0.0.1           │      │  10.0.0.2           │
│  veth-s ────────────┼──────┼── veth-c            │
└─────────────────────┘      └─────────────────────┘
```

## Usage

### Docker

```bash
docker build -t warden .
docker run --privileged -v /tmp/data:/data warden
```

### Manual

Requires root for AF_PACKET sockets and network namespaces:

```bash
sudo bash run.sh
```

### Server Options

- `--json` - Path to JSON payload file (default: `/data/sample.json`)
- `--repeat` - Number of times to repeat payload (default: 1000)
- `--tamper` - Flip one byte in frame 15 to simulate tampering

## JSON Payload Format

```json
{
  "text": "payload content"
}
```

## Tests

`run.sh` performs two tests:

1. **Reproducibility** - Captures two identical transmissions and verifies they match
2. **Tamper Detection** - Captures one tampered transmission and verifies it's detected as different

## Requirements

- Linux (for AF_PACKET and network namespaces)
- Python 3.9+
- tcpdump
- Root privileges (for network operations)

## How to Contribute

### Development Workflow

1.  **Environment**: All development and testing should be performed within the Docker container to ensure reproducible network conditions (namespaces, veth pairs).
2.  **Code Changes**: Modify the Python scripts (`server.py`, `client.py`, `analyze.py`) locally.
3.  **Verification**: Re-build and run the container to verify changes.

### Running the Test Suite

The `run.sh` script is the single source of truth for verification. It orchestrates network setup, runs scenarios, captures traffic, and performs analysis.

To run the full suite and export results to your local `data/` directory:

```bash
# Build the image
docker build -t warden .

# Run tests with volume mount
docker run --privileged --rm -v $(pwd)/data:/data warden ./run.sh
```

### Analyzing Results

The test suite generates several artifacts in the `data/` directory:

1.  **`results_summary.txt`**: High-level pass/fail status and detailed Timing Analysis reports.
2.  **`results.html`**: A visual packet-by-packet comparison of traffic captures.
3.  **`capture_*.pcap`**: Raw PCAP files for each test trial.

### Special Features: Timing & Covert Channels

We support accurate timing analysis for detecting and mitigating covert channels.

**Timing Analysis (`analyze.py`)**:

- Use `--timing-analysis` to analyze Inter-Packet Delays (IPD).
- Calculates statistical variance and estimates covert channel bandwidth (bps).

**Comparative Analysis**:

- `analyze.py` can compare two captures (e.g., Vulnerable vs Secure) to quantify latency overhead and throughput impact.
- This is automatically run as part of `run.sh` (Tests 7 & 8).

**Manual Timing Verification Command**:

```bash
# Within the container or if you have the pcaps locally:
python3 analyze.py --timing-analysis data/capture_7.pcap data/capture_8.pcap
```
