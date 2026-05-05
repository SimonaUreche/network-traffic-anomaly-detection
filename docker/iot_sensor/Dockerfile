FROM ubuntu:22.04
# ii spun sistemului sa nu intrebe nimic atunci cand instaleaza programe -> sa nu astepte raspuns de la tastatura  
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq \
    && apt-get install -y -qq \
        tcpdump \
        mosquitto-clients \
        iputils-ping \
        iptables \
        bc \
    && rm -rf /var/lib/apt/lists/*

COPY traffic_normal.sh /scripts/traffic_normal.sh
RUN chmod +x /scripts/traffic_normal.sh

CMD ["/scripts/traffic_normal.sh"]
