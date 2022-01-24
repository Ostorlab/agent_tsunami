#Stage 1.
FROM adoptopenjdk/openjdk13:debianslim as tsunami_builder

## Install dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates
#
WORKDIR /usr/tsunami/repos


# Clone the plugins repo
RUN git clone --depth 1 "https://github.com/google/tsunami-security-scanner-plugins"

# Build plugins
WORKDIR /usr/tsunami/repos/tsunami-security-scanner-plugins/google
RUN chmod +x build_all.sh \
    && ./build_all.sh

RUN mkdir /usr/tsunami/plugins \
    && cp build/plugins/*.jar /usr/tsunami/plugins

# Compile the Tsunami scanner
RUN git clone --depth 1 "https://github.com/google/tsunami-security-scanner.git" /usr/repos/tsunami-security-scanner
WORKDIR /usr/repos/tsunami-security-scanner
RUN ./gradlew shadowJar \
    && cp $(find "./" -name 'tsunami-main-*-cli.jar') /usr/tsunami/tsunami.jar \
    && cp ./tsunami.yaml /usr/tsunami


#Stage 2.
FROM python:3.8-alpine as base
FROM base as builder
RUN apk add --no-cache ca-certificates git make gcc libc-dev g++ autoconf


RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt

# Compile ncrack
RUN git clone https://github.com/nmap/ncrack /opt/ncrack &&\
	cd /opt/ncrack &&\
	./configure &&\
	make &&\
	make install




FROM base
# Install dependencies
RUN apk add nmap ca-certificates openjdk8 nmap-scripts
WORKDIR /usr/tsunami
COPY --from=tsunami_builder /usr/tsunami /usr/tsunami
RUN mkdir -p /usr/tsunami/logs

COPY --from=builder /usr/local/bin/ncrack /usr/local/bin/ncrack
COPY --from=builder /usr/local/share/ncrack /usr/local/share/ncrack
COPY --from=builder /install /usr/local

COPY src /app
WORKDIR /app
CMD ["watch", "ls"]