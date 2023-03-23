#Stage 1.
FROM adoptopenjdk/openjdk13:debianslim as tsunami_builder

## Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates

# Clone the plugins repo
WORKDIR /usr/tsunami/repos
RUN git clone --depth 1 "https://github.com/google/tsunami-security-scanner-plugins"

# Build plugins
WORKDIR /usr/tsunami/repos/tsunami-security-scanner-plugins/google
RUN chmod +x build_all.sh && ./build_all.sh

RUN mkdir /usr/tsunami/plugins && cp build/plugins/*.jar /usr/tsunami/plugins

# Compile the Tsunami scanner
RUN git clone --depth 1 "https://github.com/google/tsunami-security-scanner.git" /usr/repos/tsunami-security-scanner
WORKDIR /usr/repos/tsunami-security-scanner
RUN ./gradlew shadowJar \
    && cp $(find "./" -name 'tsunami-main-*-cli.jar') /usr/tsunami/tsunami.jar \
    && cp ./tsunami.yaml /usr/tsunami


FROM ubuntu:22.04
# Install dependencies
RUN apt update && apt install -y --no-install-recommends nmap ncrack ca-certificates openjdk-11-jre wireguard-tools openresolv iptables iproute2 python3-pip && rm -rf /var/lib/apt/lists/*

COPY --from=tsunami_builder /usr/tsunami /usr/tsunami
RUN mkdir -p /usr/tsunami/logs

RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install -r /requirement.txt


RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app/agent
CMD ["python3", "/app/agent/tsunami_agent.py"]
