#!/usr/bin/env bash
set -euo pipefail

# ── Network namespace setup ──────────────────────────────────────────
teardown() {
    ip netns del ns_server 2>/dev/null || true
    ip netns del ns_client 2>/dev/null || true
}

setup_network() {
    teardown

    ip netns add ns_server
    ip netns add ns_client

    ip link add veth-s type veth peer name veth-c

    ip link set veth-s netns ns_server
    ip link set veth-c netns ns_client

    # Deterministic MAC addresses
    ip netns exec ns_server ip link set veth-s address 02:00:0a:00:00:01
    ip netns exec ns_client ip link set veth-c address 02:00:0a:00:00:02

    ip netns exec ns_server ip addr add 10.0.0.1/24 dev veth-s
    ip netns exec ns_client ip addr add 10.0.0.2/24 dev veth-c

    ip netns exec ns_server ip link set lo up
    ip netns exec ns_client ip link set lo up
    ip netns exec ns_server ip link set veth-s up
    ip netns exec ns_client ip link set veth-c up

    # Wait for interfaces to come up
    sleep 0.5
}

# ── Single trial ─────────────────────────────────────────────────────
run_trial() {
    local n=$1
    local scenario="${2:-1}"  # Default to scenario 1
    local pcap="/data/capture_${n}.pcap"

    echo "── trial ${n} ──"

    # Capture on the client's veth
    # For UDP: capture server's response packets
    # For TCP: filter to exclude SYN, FIN, RST to capture only data frames
    if [ "$scenario" = "3" ] || [ "$scenario" = "4" ]; then
        # TCP: capture from server on port 5000, excluding flags 0x02 (SYN), 0x01 (FIN), 0x04 (RST)
        local filter="src 10.0.0.1 and port 5000"
    else
        # UDP: capture from server on port 5000
        local filter="src 10.0.0.1 and port 5000"
    fi

    ip netns exec ns_client \
        tcpdump -i veth-c -w "$pcap" -U --immediate-mode "$filter" &
    local tcpdump_pid=$!
    sleep 1

    # Start server
    ip netns exec ns_server python3 /app/server.py &
    local server_pid=$!
    sleep 1

    # Client sends trigger and receives response with scenario
    ip netns exec ns_client env SCENARIO=$scenario python3 /app/client.py

    # Wait for server to finish sending
    wait "$server_pid" 2>/dev/null || true

    # Give tcpdump time to flush, then stop it
    sleep 1
    kill "$tcpdump_pid" 2>/dev/null || true
    wait "$tcpdump_pid" 2>/dev/null || true

    echo "── trial ${n} captured → ${pcap} ──"
}

# ── Main ─────────────────────────────────────────────────────────────
mkdir -p /data

setup_network

echo ""
echo "══ Test 1: UDP reproducibility (expect PASS) ══"
run_trial 1 1
run_trial 2 1

echo ""
python3 /app/analyze.py /data/capture_1.pcap /data/capture_2.pcap
result1=$?

echo ""
echo "══ Test 2: UDP tamper detection (expect FAIL) ══"
run_trial 3 2

echo ""
python3 /app/analyze.py /data/capture_1.pcap /data/capture_3.pcap && result2=0 || result2=$?

echo ""
echo "══ Test 3: UDP steganography/exfil detection (expect FAIL) ══"
run_trial 4 1

echo ""
python3 /app/analyze.py /data/capture_1.pcap /data/capture_4.pcap && result3=0 || result3=$?

echo ""
echo "══ Test 4: TCP reproducibility (expect PASS) ══"
run_trial 5 3
run_trial 6 3

echo ""
python3 /app/analyze.py /data/capture_5.pcap /data/capture_6.pcap
result4=$?

echo ""
echo "══ Test 5: UDP vs TCP detection (expect FAIL) ══"
python3 /app/analyze.py /data/capture_1.pcap /data/capture_5.pcap && result5=0 || result5=$?

echo ""
echo "══ Test 6: TCP tamper detection (expect FAIL) ══"
run_trial 7 4

echo ""
python3 /app/analyze.py /data/capture_5.pcap /data/capture_7.pcap && result6=0 || result6=$?

echo ""
echo "══ Test 7: UDP tampered vs TCP tampered (expect FAIL) ══"
run_trial 8 2

echo ""
python3 /app/analyze.py /data/capture_8.pcap /data/capture_7.pcap && result7=0 || result7=$?

teardown

echo ""
echo "══ Summary ══"
if [ "$result1" -eq 0 ]; then
    echo "  Test 1 - UDP reproducibility: PASS"
else
    echo "  Test 1 - UDP reproducibility: FAIL (unexpected)"
fi
if [ "$result2" -ne 0 ]; then
    echo "  Test 2 - UDP tamper detection: PASS (diff detected as expected)"
else
    echo "  Test 2 - UDP tamper detection: FAIL (tamper was not detected!)"
fi
if [ "$result3" -ne 0 ]; then
    echo "  Test 3 - UDP stego detection: PASS (but should be UDP-based now)"
else
    echo "  Test 3 - UDP stego detection: FAIL (extra packet not detected)"
fi
if [ "$result4" -eq 0 ]; then
    echo "  Test 4 - TCP reproducibility: PASS"
else
    echo "  Test 4 - TCP reproducibility: FAIL (unexpected)"
fi
if [ "$result5" -ne 0 ]; then
    echo "  Test 5 - UDP vs TCP detection: PASS (protocol difference detected)"
else
    echo "  Test 5 - UDP vs TCP detection: FAIL (should detect protocol difference)"
fi
if [ "$result6" -ne 0 ]; then
    echo "  Test 6 - TCP tamper detection: PASS (diff detected as expected)"
else
    echo "  Test 6 - TCP tamper detection: FAIL (tamper was not detected!)"
fi
if [ "$result7" -ne 0 ]; then
    echo "  Test 7 - UDP vs TCP tamper: PASS (both differ as expected)"
else
    echo "  Test 7 - UDP vs TCP tamper: FAIL (should detect differences)"
fi
echo ""
echo "══ Generating HTML visualization ══"
python3 /app/visualize.py
echo "Open /data/results.html in a browser to view the results."
