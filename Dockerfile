FROM ghcr.io/google/tsunami-scanner-full:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y --no-install-recommends \
        nmap ncrack wireguard-tools iptables iproute2 \
        python3.14 python3.14-dev python3.14-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3.14 -m venv /app/venv
COPY requirement.txt /requirement.txt
RUN /app/venv/bin/pip install --upgrade pip && /app/venv/bin/pip install -r /requirement.txt

RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app/agent
CMD ["/app/venv/bin/python", "/app/agent/tsunami_agent.py"]
