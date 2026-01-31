"""
Warden client: sends a UDP trigger to the server, then receives the response.
The trigger is a JSON payload with a "text" field (matching the fixture format),
but nothing from the trigger is used by the server — the response is precomputed.
"""

import socket
import json
import hashlib
import sys

SERVER_IP = "10.0.0.1"
CLIENT_IP = "10.0.0.2"
UDP_PORT = 5000
RECV_TIMEOUT = 3  # seconds


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((CLIENT_IP, UDP_PORT))

    trigger = json.dumps({"text": "hello"}).encode()
    sock.sendto(trigger, (SERVER_IP, UDP_PORT))
    print("[client] trigger sent", flush=True)

    chunks = []
    sock.settimeout(RECV_TIMEOUT)
    try:
        while True:
            chunk, _ = sock.recvfrom(65535)
            chunks.append(chunk)
    except socket.timeout:
        pass

    payload = b"".join(chunks)
    h = hashlib.sha256(payload).hexdigest()
    print(f"[client] received {len(payload)} bytes, sha256={h}", flush=True)
    sock.close()


if __name__ == "__main__":
    main()
