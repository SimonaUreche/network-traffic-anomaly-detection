FROM ubuntu:22.04


ENV DEBIAN_FRONTEND=noninteractive  

# executam o comanda in timpul byuil-ului imaginii
RUN apt-get update -qq \
    && apt-get install -y -qq \
        iptables \
        iputils-ping \
        openssh-server \
        tcpdump \
    && rm -rf /var/lib/apt/lists/* 

# configurare ssh intetionat nesigur
# cream folderul pt ssh
# setam parola intetionat slaba
# modificam configatia ssh pt a permite login ca root (implicit deactivat in ubuntu)
# modificam configutatia ssh pt a permite autentificarea cu parola(vs doar chei ssh)
RUN mkdir -p /run/sshd \
    && echo 'root:password123' | chpasswd \
    && sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

WORKDIR /scripts

COPY start.sh /scripts/start.sh
COPY traffic_normal.sh /scripts/traffic_normal.sh

RUN chmod +x /scripts/start.sh /scripts/traffic_normal.sh

CMD ["/scripts/start.sh"]

# openssh-server - serverul ssh care va rula pe serverul de auth pentru a putea testa atacul de ssh brute-force
# iputils-ping - pentru a putea face ping la gateway din serverul de auth
# iptables - blocsre atacator
# tcpdump - pentru a putea captura traficul de retea
