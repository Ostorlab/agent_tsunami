# Tsunami core engine and plugins
FROM ghcr.io/google/tsunami-scanner-core:latest AS core
FROM ghcr.io/google/tsunami-plugins-google:latest AS plugins-google
FROM ghcr.io/google/tsunami-plugins-templated:latest AS plugins-templated
FROM ghcr.io/google/tsunami-plugins-doyensec:latest AS plugins-doyensec
FROM ghcr.io/google/tsunami-plugins-community:latest AS plugins-community
FROM ghcr.io/google/tsunami-plugins-govtech:latest AS plugins-govtech
FROM ghcr.io/google/tsunami-plugins-facebook:latest AS plugins-facebook
FROM ghcr.io/google/tsunami-plugins-python:latest AS plugins-python

FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates openjdk-21-jre \
        nmap ncrack wireguard-tools iptables iproute2 \
        python3.14 python3.14-dev python3.14-venv \
    && rm -rf /var/lib/apt/lists/*

COPY --from=core /usr/tsunami/ /usr/tsunami/
COPY --from=plugins-google /usr/tsunami/plugins/ /usr/tsunami/plugins/
COPY --from=plugins-templated /usr/tsunami/plugins/ /usr/tsunami/plugins/
COPY --from=plugins-doyensec /usr/tsunami/plugins/ /usr/tsunami/plugins/
COPY --from=plugins-community /usr/tsunami/plugins/ /usr/tsunami/plugins/
COPY --from=plugins-govtech /usr/tsunami/plugins/ /usr/tsunami/plugins/
COPY --from=plugins-facebook /usr/tsunami/plugins/ /usr/tsunami/plugins/
COPY --from=plugins-python /usr/tsunami/py_plugins/ /usr/tsunami/py_plugins/
RUN mkdir -p /usr/tsunami/logs

RUN python3.14 -m venv /app/venv
COPY requirement.txt /requirement.txt
RUN /app/venv/bin/pip install --upgrade pip && /app/venv/bin/pip install -r /requirement.txt

RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app/agent
CMD ["/app/venv/bin/python", "/app/agent/tsunami_agent.py"]
