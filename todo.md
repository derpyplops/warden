# Project TODOs

## Adding Core Simulation Logic (Stretch Goal)

- [ ] **Simulate API Traffic Flow**:
  - Simulate distinct traffic directions:
    - **Prover Side**: What arrives at the prover?
    - **Verifier Side**: What data (hashes) does the verifier receive?
    - **Data Center Side**: What scrubbed packets arrive at the data center?
  - Define exact payload for hashing (e.g., one TCP segment's payload per hash).

- [ ] **Border Patrol Device Features**:
  - [ ] **Scrubbing Logic**: Ensure rigorous scrubbing of protocol headers.
  - [ ] **State Tables**: Implement state tracking for:
    - TCP Initial Sequence Numbers (ISNs) (handling man-in-the-middle handshake modifications).
    - Source/Destination Port translations.
  - [ ] **Coin Flip**: Simulate what the coin flip devices observe.

## Visualization & Demo (High Priority rn)

- [ ] **Packet Journey Visualization**:
  - Show an example packet (e.g., one API stream open) moving through the system.
  - Visualize the "Split":
    - Prover sees the traffic.
    - Verifier gets the hashes.
    - Data Center gets scrubbed packets.
  - _Goal_: "Transparency so that they [both parties] feel that they can trust it."

## Stretch Goals

- [ ] **Verification/Challenge Mockup**: Simulate the process of using stored hashes to challenge the prover later (replay verification).
- [ ] **Designer Dashboard**: A UI to show the state of the system and transparency metrics.
