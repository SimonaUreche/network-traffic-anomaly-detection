FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq \
    && apt-get install -y -qq \
        dnsmasq \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY dnsmasq.conf /etc/dnsmasq.conf
COPY dnsmasq.hosts /etc/dnsmasq.hosts
COPY start.sh /scripts/start.sh

RUN chmod +x /scripts/start.sh

CMD ["/scripts/start.sh"]
