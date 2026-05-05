FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq \
    mosquitto-clients \
    nmap \
    hping3 \
    netcat-openbsd \
    sshpass \
    bash \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY normal.sh /normal.sh
COPY attack/portscan.sh /attack/portscan.sh
COPY attack/ddos.sh /attack/ddos.sh
COPY attack/bruteforce.sh /attack/bruteforce.sh
RUN chmod +x /normal.sh /attack/*.sh
CMD ["/normal.sh"]