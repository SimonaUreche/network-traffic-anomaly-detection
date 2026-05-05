FROM alpine:3.18
RUN apk add --no-cache \
    mosquitto-clients \
    curl \
    bash \
    tcpdump \
    nginx

RUN mkdir -p /var/www/html && cat > /var/www/html/index.html <<'EOF'
<!DOCTYPE html>
<html>
<head><title>Smart Camera - cam_001</title></head>
<body>
<h1>Smart Camera Configuration</h1>
<p>Model: IoT-Cam 3000</p>
<p>Firmware: 3.2.1</p>
<p>Status: Recording</p>
<p>Resolution: 1080p / 25fps</p>
</body>
</html>
EOF

RUN echo 'server { listen 80; root /var/www/html; }' > /etc/nginx/http.d/default.conf

COPY normal.sh /normal.sh
COPY start.sh /start.sh
RUN chmod +x /normal.sh /start.sh

CMD ["/start.sh"]