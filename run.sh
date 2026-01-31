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
    local pcap="/data/capture_${n}.pcap"

    echo "── trial ${n} ──"

    # Capture on the client's veth — server egress arrives here as ingress.
    # Filter: UDP only from the server (excludes ARP and the client trigger).
    ip netns exec ns_client \
        tcpdump -i veth-c -w "$pcap" -U --immediate-mode \
        'udp and src host 10.0.0.1' &
    local tcpdump_pid=$!
    sleep 1

    local server_flags="${2:-}"

    # Start server (blocks until trigger, sends, exits)
    ip netns exec ns_server python3 /app/server.py $server_flags &
    local server_pid=$!
    sleep 1

    # Client sends trigger and receives response
    ip netns exec ns_client python3 /app/client.py

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
echo "══ Test 1: reproducibility (expect PASS) ══"
run_trial 1
run_trial 2

echo ""
python3 /app/analyze.py /data/capture_1.pcap /data/capture_2.pcap
result1=$?

echo ""
echo "══ Test 2: tamper detection (expect FAIL) ══"
run_trial 3 "--tamper"

echo ""
python3 /app/analyze.py /data/capture_1.pcap /data/capture_3.pcap && result2=0 || result2=$?

teardown

echo ""
echo "══ Summary ══"
if [ "$result1" -eq 0 ]; then
    echo "  reproducibility : PASS"
else
    echo "  reproducibility : FAIL (unexpected)"
fi
if [ "$result2" -ne 0 ]; then
    echo "  tamper detection: PASS (diff detected as expected)"
else
    echo "  tamper detection: FAIL (tamper was not detected!)"
fi
