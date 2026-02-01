FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        tcpdump \
        jq \
    && rm -rf /var/lib/apt/lists/*

# Install scapy for packet manipulation
RUN pip install --no-cache-dir scapy

WORKDIR /app

COPY server.py client.py analyze.py visualize.py collect_hashes.py augment_hash.py run.sh sample.json ./

RUN chmod +x run.sh

CMD ["./run.sh"]
