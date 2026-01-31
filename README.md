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
