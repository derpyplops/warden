"""
Generate HTML visualizations comparing pcap captures.
"""

import struct
import sys
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Packet:
    raw: bytes
    eth_src: str
    eth_dst: str
    ethertype: int
    ip_src: Optional[str]
    ip_dst: Optional[str]
    ip_proto: Optional[int]
    src_port: Optional[int]
    dst_port: Optional[int]
    payload: bytes


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def ip_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def read_pcap(path: str) -> list[bytes]:
    packets = []
    with open(path, "rb") as f:
        ghdr = f.read(24)
        if len(ghdr) < 24:
            raise ValueError(f"Truncated pcap: {path}")
        magic = struct.unpack("<I", ghdr[:4])[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
        elif magic == 0xD4C3B2A1:
            endian = ">"
        else:
            raise ValueError(f"Bad magic in {path}: {hex(magic)}")

        while True:
            phdr = f.read(16)
            if len(phdr) < 16:
                break
            _, _, incl_len, _ = struct.unpack(endian + "IIII", phdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            packets.append(data)
    return packets


def parse_packet(raw: bytes) -> Packet:
    eth_dst = mac_str(raw[0:6])
    eth_src = mac_str(raw[6:12])
    ethertype = struct.unpack("!H", raw[12:14])[0]

    ip_src = ip_dst = None
    ip_proto = None
    src_port = dst_port = None
    payload = b""

    if ethertype == 0x0800 and len(raw) >= 34:  # IPv4
        ip = 14
        ihl = (raw[ip] & 0x0F) * 4
        ip_proto = raw[ip + 9]
        ip_src = ip_str(raw[ip + 12 : ip + 16])
        ip_dst = ip_str(raw[ip + 16 : ip + 20])

        if ip_proto == 17 and len(raw) >= ip + ihl + 8:  # UDP
            udp = ip + ihl
            src_port = struct.unpack("!H", raw[udp : udp + 2])[0]
            dst_port = struct.unpack("!H", raw[udp + 2 : udp + 4])[0]
            payload = raw[udp + 8 :]
        elif ip_proto == 6 and len(raw) >= ip + ihl + 20:  # TCP
            tcp = ip + ihl
            src_port = struct.unpack("!H", raw[tcp : tcp + 2])[0]
            dst_port = struct.unpack("!H", raw[tcp + 2 : tcp + 4])[0]
            # TCP data offset is in upper 4 bits of byte 12
            tcp_data_offset = (raw[tcp + 12] >> 4) * 4
            payload_start = tcp + tcp_data_offset
            if len(raw) > payload_start:
                payload = raw[payload_start:]

    return Packet(
        raw=raw,
        eth_src=eth_src,
        eth_dst=eth_dst,
        ethertype=ethertype,
        ip_src=ip_src,
        ip_dst=ip_dst,
        ip_proto=ip_proto,
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
    )


def normalize(pkt: bytes) -> bytes:
    """Zero out volatile fields for comparison."""
    if len(pkt) < 34:
        return pkt
    buf = bytearray(pkt)
    ethertype = struct.unpack("!H", buf[12:14])[0]
    if ethertype != 0x0800:
        return bytes(buf)
    ip = 14
    buf[ip + 4] = buf[ip + 5] = 0  # IP ID
    buf[ip + 10] = buf[ip + 11] = 0  # IP checksum
    ihl = (buf[ip] & 0x0F) * 4
    proto = buf[ip + 9]
    if proto == 17 and len(buf) >= ip + ihl + 8:
        udp = ip + ihl
        buf[udp + 6] = buf[udp + 7] = 0  # UDP checksum
    return bytes(buf)


def payload_preview(data: bytes, max_len: int = 48) -> str:
    try:
        text = data.decode("utf-8", errors="replace")
        if len(text) > max_len:
            text = text[:max_len] + "…"
        return text
    except:
        return data[:max_len].hex()


def generate_html(
    test_name: str,
    test_desc: str,
    cap1_path: str,
    cap2_path: str,
    expected_result: str,
) -> str:
    pkts1 = [parse_packet(p) for p in read_pcap(cap1_path)]
    pkts2 = [parse_packet(p) for p in read_pcap(cap2_path)]

    norm1 = [normalize(p.raw) for p in pkts1]
    norm2 = [normalize(p.raw) for p in pkts2]

    # Determine actual result
    matches = norm1 == norm2
    actual_result = "PASS" if matches else "FAIL"
    test_passed = (expected_result == "PASS" and matches) or (
        expected_result == "FAIL" and not matches
    )

    max_pkts = max(len(pkts1), len(pkts2))

    # Build packet rows
    rows_html = ""
    for i in range(max_pkts):
        p1 = pkts1[i] if i < len(pkts1) else None
        p2 = pkts2[i] if i < len(pkts2) else None
        n1 = norm1[i] if i < len(norm1) else None
        n2 = norm2[i] if i < len(norm2) else None

        pkt_match = n1 == n2 if (n1 and n2) else False
        row_class = "match" if pkt_match else "diff"

        def pkt_cell(p: Optional[Packet], missing: bool = False) -> str:
            if missing:
                return '<td class="missing"><span class="missing-label">— missing —</span></td>'
            if p is None:
                return '<td class="missing"><span class="missing-label">— missing —</span></td>'
            direction = "outgoing" if p.ip_src == "10.0.0.2" else "incoming"
            payload_text = payload_preview(p.payload) if p.payload else "(empty)"
            return f"""<td class="pkt {direction}">
                <div class="pkt-header">
                    <span class="direction {'out' if direction == 'outgoing' else 'in'}">{('→' if direction == 'outgoing' else '←')}</span>
                    <span class="endpoints">{p.ip_src}:{p.src_port} → {p.ip_dst}:{p.dst_port}</span>
                </div>
                <div class="pkt-payload">{payload_text}</div>
                <div class="pkt-size">{len(p.raw)} bytes</div>
            </td>"""

        rows_html += f"""
        <tr class="{row_class}">
            <td class="idx">{i}</td>
            {pkt_cell(p1, missing=(p1 is None))}
            <td class="status">{'✓' if pkt_match else '✗'}</td>
            {pkt_cell(p2, missing=(p2 is None))}
        </tr>
        """

    status_class = "success" if test_passed else "failure"
    status_icon = "✓" if test_passed else "✗"

    return f"""
    <div class="test-card {status_class}">
        <div class="test-header">
            <div class="test-title">
                <span class="test-icon">{status_icon}</span>
                <h2>{test_name}</h2>
            </div>
            <div class="test-meta">
                <span class="badge expected">Expected: {expected_result}</span>
                <span class="badge actual">Actual: {actual_result}</span>
            </div>
        </div>
        <p class="test-desc">{test_desc}</p>
        <div class="captures-info">
            <span class="cap-label">Capture 1:</span> {os.path.basename(cap1_path)} ({len(pkts1)} packets)
            <span class="cap-label">Capture 2:</span> {os.path.basename(cap2_path)} ({len(pkts2)} packets)
        </div>
        <table class="packets-table">
            <thead>
                <tr>
                    <th class="idx-header">#</th>
                    <th>Capture 1</th>
                    <th class="status-header"></th>
                    <th>Capture 2</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
    """


def generate_text_report(title: str, file_path: str) -> str:
    if not os.path.exists(file_path):
        return f"""
        <div class="test-card failure">
            <div class="test-header">
                <div class="test-title">
                    <span class="test-icon">✗</span>
                    <h2>{title}</h2>
                </div>
            </div>
            <p class="test-desc">Report file missing: {file_path}</p>
        </div>
        """
        
    with open(file_path, "r") as f:
        content = f.read()
        
    return f"""
    <div class="test-card">
        <div class="test-header">
            <div class="test-title">
                <span class="test-icon">ℹ</span>
                <h2>{title}</h2>
            </div>
        </div>
        <div class="pkt-payload" style="max-width: none; white-space: pre-wrap; font-family: 'JetBrains Mono', monospace; color: var(--text-dim); background: var(--bg-elevated); padding: 1rem; border-radius: 8px;">{content}</div>
    </div>
    """


def main():
    html_parts = []

    tests = [
        (
            "Test 1: UDP Reproducibility",
            "Two identical UDP runs (scenario 1) should produce identical (normalized) traffic.",
            "/data/capture_1.pcap",
            "/data/capture_2.pcap",
            "PASS",
        ),
        (
            "Test 2: UDP Tamper Detection",
            "Server tampers byte 50 of UDP payload (scenario 2). The difference should be detected.",
            "/data/capture_1.pcap",
            "/data/capture_3.pcap",
            "FAIL",
        ),
        (
            "Test 3: TCP Scenario 3 (Normal)",
            "TCP connection with normal data transfer (scenario 3). Shows handshake and data frames.",
            "/data/capture_4.pcap",
            "/data/capture_4.pcap",
            "PASS",
        ),
        (
            "Test 4: TCP Scenario 4 (Tampered)",
            "TCP connection with tampered payload (scenario 4). Byte 50 in payload is XORed.",
            "/data/capture_5.pcap",
            "/data/capture_5.pcap",
            "PASS",
        ),
        (
            "Test 5: TCP Steganography Detection",
            "TCP with secret message hidden in IP option padding (scenario 5) vs normal TCP (scenario 3). Should detect covert channel.",
            "/data/capture_4.pcap",
            "/data/capture_6.pcap",
            "FAIL",
        ),
        (
            "Test 6: Steganography Defeated (IP Options Zeroed)",
            "Comparing normal Capture 4 vs Stego Capture 6. Note: visualize.py uses standard normalization (preserves options), so packet structure differences will be visible.",
            "/data/capture_4.pcap",
            "/data/capture_6.pcap",
            "FAIL",
        ),
    ]

    for test_name, test_desc, cap1, cap2, expected in tests:
        if os.path.exists(cap1) and os.path.exists(cap2):
            html_parts.append(generate_html(test_name, test_desc, cap1, cap2, expected))

    # Add Timing Analysis Reports
    html_parts.append(generate_text_report("Test 7: Covert Timing Analysis (Vulnerable)", "/data/test7_analysis.txt"))
    html_parts.append(generate_text_report("Test 8: Covert Timing Analysis (Secure)", "/data/test8_analysis.txt"))
    html_parts.append(generate_text_report("Comparative Latency Analysis", "/data/timing_comparison.txt"))

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Warden Test Results</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@400;600;700&display=swap');

        :root {{
            --bg-dark: #0a0a0f;
            --bg-card: #12121a;
            --bg-elevated: #1a1a24;
            --border: #2a2a3a;
            --text: #e4e4eb;
            --text-dim: #8888a0;
            --accent-cyan: #00d4ff;
            --accent-green: #00ff9d;
            --accent-red: #ff4d6a;
            --accent-orange: #ffa64d;
            --accent-purple: #b44dff;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Space Grotesk', sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
            padding: 2rem;
            background-image: 
                radial-gradient(ellipse at 20% 0%, rgba(0, 212, 255, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 100%, rgba(180, 77, 255, 0.08) 0%, transparent 50%);
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        header {{
            text-align: center;
            margin-bottom: 3rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
        }}

        h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}

        .subtitle {{
            color: var(--text-dim);
            font-size: 1.1rem;
        }}

        .test-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            overflow: hidden;
        }}

        .test-card.success {{
            border-left: 4px solid var(--accent-green);
        }}

        .test-card.failure {{
            border-left: 4px solid var(--accent-red);
        }}

        .test-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}

        .test-title {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .test-icon {{
            font-size: 1.5rem;
        }}

        .success .test-icon {{
            color: var(--accent-green);
        }}

        .failure .test-icon {{
            color: var(--accent-red);
        }}

        .test-title h2 {{
            font-size: 1.4rem;
            font-weight: 600;
        }}

        .test-meta {{
            display: flex;
            gap: 0.75rem;
        }}

        .badge {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            font-weight: 600;
        }}

        .badge.expected {{
            background: var(--bg-elevated);
            color: var(--text-dim);
        }}

        .badge.actual {{
            background: var(--bg-elevated);
            color: var(--accent-cyan);
        }}

        .test-desc {{
            color: var(--text-dim);
            margin-bottom: 1rem;
            line-height: 1.6;
        }}

        .captures-info {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-dim);
            margin-bottom: 1.5rem;
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
        }}

        .cap-label {{
            color: var(--accent-purple);
            margin-right: 0.5rem;
        }}

        .packets-table {{
            width: 100%;
            border-collapse: collapse;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }}

        .packets-table th {{
            background: var(--bg-elevated);
            padding: 0.75rem 1rem;
            text-align: left;
            font-weight: 600;
            color: var(--text-dim);
            border-bottom: 1px solid var(--border);
        }}

        .packets-table th.idx-header,
        .packets-table th.status-header {{
            width: 50px;
            text-align: center;
        }}

        .packets-table td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}

        .packets-table tr:last-child td {{
            border-bottom: none;
        }}

        .packets-table tr.match {{
            background: rgba(0, 255, 157, 0.03);
        }}

        .packets-table tr.diff {{
            background: rgba(255, 77, 106, 0.05);
        }}

        .idx {{
            text-align: center;
            color: var(--text-dim);
            font-weight: 600;
        }}

        .status {{
            text-align: center;
            font-size: 1.2rem;
        }}

        .match .status {{
            color: var(--accent-green);
        }}

        .diff .status {{
            color: var(--accent-red);
        }}

        .pkt {{
            background: var(--bg-elevated);
            border-radius: 8px;
            padding: 0.75rem !important;
        }}

        .pkt.incoming {{
            border-left: 3px solid var(--accent-cyan);
        }}

        .pkt.outgoing {{
            border-left: 3px solid var(--accent-orange);
        }}

        .pkt-header {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }}

        .direction {{
            font-size: 1rem;
            font-weight: 700;
        }}

        .direction.in {{
            color: var(--accent-cyan);
        }}

        .direction.out {{
            color: var(--accent-orange);
        }}

        .endpoints {{
            color: var(--text);
            font-size: 0.8rem;
        }}

        .pkt-payload {{
            color: var(--accent-green);
            word-break: break-all;
            margin-bottom: 0.35rem;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .pkt-size {{
            color: var(--text-dim);
            font-size: 0.75rem;
        }}

        .missing {{
            text-align: center;
        }}

        .missing-label {{
            color: var(--accent-red);
            font-style: italic;
            opacity: 0.7;
        }}

        .legend {{
            display: flex;
            gap: 2rem;
            justify-content: center;
            margin-top: 2rem;
            padding: 1rem;
            background: var(--bg-card);
            border-radius: 12px;
            flex-wrap: wrap;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
            color: var(--text-dim);
        }}

        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 3px;
        }}

        .legend-color.incoming {{
            background: var(--accent-cyan);
        }}

        .legend-color.outgoing {{
            background: var(--accent-orange);
        }}

        .legend-color.match {{
            background: var(--accent-green);
        }}

        .legend-color.diff {{
            background: var(--accent-red);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>⚔ Warden Test Results</h1>
            <p class="subtitle">Network Traffic Reproducibility Analysis</p>
        </header>

        {''.join(html_parts)}

        <div class="legend">
            <div class="legend-item">
                <div class="legend-color incoming"></div>
                <span>Incoming (from server)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color outgoing"></div>
                <span>Outgoing (from client)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color match"></div>
                <span>Packets match</span>
            </div>
            <div class="legend-item">
                <div class="legend-color diff"></div>
                <span>Packets differ</span>
            </div>
        </div>
    </div>
</body>
</html>
"""

    output_path = "/data/results.html"
    with open(output_path, "w") as f:
        f.write(full_html)
    print(f"Visualization written to {output_path}")


if __name__ == "__main__":
    main()
