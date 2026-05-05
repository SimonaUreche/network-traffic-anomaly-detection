FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq \
    && apt-get install -y -qq \
        nginx \
        curl \
        iputils-ping \
        iptables \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

# nginx vine cu o pagina default — e suficient
# fara HTML custom
RUN mkdir -p /var/www/html/firmware
COPY firmware_check.json /var/www/html/firmware/check

WORKDIR /scripts
COPY start.sh /scripts/start.sh
COPY traffic_normal.sh /scripts/traffic_normal.sh
RUN chmod +x /scripts/start.sh /scripts/traffic_normal.sh

CMD ["/scripts/start.sh"]