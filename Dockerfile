FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY server.py client.py analyze.py visualize.py run.sh sample.json ./

RUN chmod +x run.sh

CMD ["./run.sh"]
