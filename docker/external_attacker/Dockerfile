FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    hping3 \
    nmap \
    sshpass \
    apache2-utils \
    mosquitto-clients \
    slowhttptest \
    net-tools \
    iproute2 \
    iputils-ping \
    curl \
    wget \
    nano \
    && rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]