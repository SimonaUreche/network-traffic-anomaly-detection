FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq \
    && apt-get install -y -qq \
        curl \
        iputils-ping \
        dnsutils \
        mosquitto \
        mosquitto-clients \
        openssh-client \
        sshpass \
        iptables \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY start.sh /scripts/start.sh
COPY traffic_normal.sh /scripts/traffic_normal.sh
COPY mosquitto.conf /etc/mosquitto/mosquitto.conf

RUN chmod +x /scripts/start.sh /scripts/traffic_normal.sh

CMD ["/scripts/start.sh"]
