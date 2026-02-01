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

    echo "── trial ${n} (scenario ${scenario}) ──"

    # Capture only packets FROM server (src 10.0.0.1)
    # This includes UDP responses and TCP handshake/data (SYN-ACK, data, FIN-ACK)
    # Excludes outgoing trigger packets from client
    local filter="src 10.0.0.1"

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
echo "════════════════════════════════════════════════════════════════"
echo "Test 1: UDP Reproducibility (Scenario 1 × 2)"
echo "════════════════════════════════════════════════════════════════"
run_trial 1 1
run_trial 2 1

echo ""
python3 /app/analyze.py /data/capture_1.pcap /data/capture_2.pcap | tee /data/test1_analysis.txt
test1_result=$?

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Test 2: UDP Tamper Detection (Scenario 1 vs Scenario 2)"
echo "════════════════════════════════════════════════════════════════"
run_trial 3 2

echo ""
# Test 2 PASSES if analyze.py detects difference (exit code 1)
python3 /app/analyze.py /data/capture_1.pcap /data/capture_3.pcap | tee /data/test2_analysis.txt && test2_result=0 || test2_result=1

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Test 3: TCP Scenario 3 Functional (Normal)"
echo "════════════════════════════════════════════════════════════════"
run_trial 4 3
test3_result=0

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Test 4: TCP Scenario 4 Functional (Tampered)"
echo "════════════════════════════════════════════════════════════════"
run_trial 5 4
test4_result=0

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Test 5: TCP Steganography Detection (Scenario 3 vs 5)"
echo "════════════════════════════════════════════════════════════════"
run_trial 6 5

echo ""
# Compare scenario 3 (normal TCP) vs scenario 5 (TCP with IP padding stego)
python3 /app/analyze.py /data/capture_4.pcap /data/capture_6.pcap | tee /data/test5_analysis.txt && test5_result=0 || test5_result=1

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Test 6: Steganography Defeated by IP Options Zeroing"
echo "════════════════════════════════════════════════════════════════"
echo "Same comparison as Test 5, but with IP options zeroed out"
echo ""
# Compare with --zero-ip-options flag to defeat steganography detection
python3 /app/analyze.py --zero-ip-options /data/capture_4.pcap /data/capture_6.pcap | tee /data/test6_analysis.txt && test6_result=0 || test6_result=1

teardown

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "SUMMARY"
echo "════════════════════════════════════════════════════════════════"

# Create summary file
{
    echo "════════════════════════════════════════════════════════════════"
    echo "WARDEN TEST RESULTS"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "Test Results:"
    echo ""
} > /data/results_summary.txt

if [ "$test1_result" -eq 0 ]; then
    echo "✓ Test 1: UDP Reproducibility - PASS"
    echo "✓ Test 1: UDP Reproducibility - PASS" >> /data/results_summary.txt
else
    echo "✗ Test 1: UDP Reproducibility - FAIL"
    echo "✗ Test 1: UDP Reproducibility - FAIL" >> /data/results_summary.txt
fi

if [ "$test2_result" -eq 1 ]; then
    echo "✓ Test 2: UDP Tamper Detection - PASS (difference detected)"
    echo "✓ Test 2: UDP Tamper Detection - PASS (difference detected)" >> /data/results_summary.txt
else
    echo "✗ Test 2: UDP Tamper Detection - FAIL"
    echo "✗ Test 2: UDP Tamper Detection - FAIL" >> /data/results_summary.txt
fi

if [ "$test3_result" -eq 0 ]; then
    echo "✓ Test 3: TCP Scenario 3 - PASS"
    echo "✓ Test 3: TCP Scenario 3 - PASS" >> /data/results_summary.txt
else
    echo "✗ Test 3: TCP Scenario 3 - FAIL"
    echo "✗ Test 3: TCP Scenario 3 - FAIL" >> /data/results_summary.txt
fi

if [ "$test4_result" -eq 0 ]; then
    echo "✓ Test 4: TCP Scenario 4 - PASS"
    echo "✓ Test 4: TCP Scenario 4 - PASS" >> /data/results_summary.txt
else
    echo "✗ Test 4: TCP Scenario 4 - FAIL"
    echo "✗ Test 4: TCP Scenario 4 - FAIL" >> /data/results_summary.txt
fi

if [ "$test5_result" -eq 1 ]; then
    echo "✓ Test 5: TCP Steganography Detection - PASS (difference detected)"
    echo "✓ Test 5: TCP Steganography Detection - PASS (difference detected)" >> /data/results_summary.txt
else
    echo "✗ Test 5: TCP Steganography Detection - FAIL"
    echo "✗ Test 5: TCP Steganography Detection - FAIL" >> /data/results_summary.txt
fi

if [ "$test6_result" -eq 1 ]; then
    echo "✓ Test 6: Steganography Defeated by IP Options Zeroing - PASS (hidden data destroyed)"
    echo "✓ Test 6: Steganography Defeated by IP Options Zeroing - PASS (hidden data destroyed)" >> /data/results_summary.txt
else
    echo "✗ Test 6: Steganography Defeated by IP Options Zeroing - FAIL (packets still differ)"
    echo "✗ Test 6: Steganography Defeated by IP Options Zeroing - FAIL (packets still differ)" >> /data/results_summary.txt
fi

{
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "ANALYSIS DETAILS"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "--- Test 1: UDP Reproducibility Analysis ---"
    echo ""
    cat /data/test1_analysis.txt
    echo ""
    echo ""
    echo "--- Test 2: UDP Tamper Detection Analysis ---"
    echo ""
    cat /data/test2_analysis.txt
    echo ""
    echo ""
    echo "--- Test 5: TCP Steganography Detection Analysis ---"
    echo ""
    cat /data/test5_analysis.txt
    echo ""
    echo ""
    echo "--- Test 6: Steganography Defeated by IP Options Zeroing ---"
    echo ""
    cat /data/test6_analysis.txt
} >> /data/results_summary.txt

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Generating HTML visualization"
echo "════════════════════════════════════════════════════════════════"
python3 /app/visualize.py
echo "Open /data/results.html in a browser to view the results."
