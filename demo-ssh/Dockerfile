FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server procps nginx iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/run/sshd \
    && useradd -m -s /bin/bash demo \
    && echo "demo:demo" | chpasswd \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config \
    && ln -s /usr/sbin/service /usr/local/bin/service \
    && printf 'Welcome to AgentGate demo SSH target\n' > /etc/motd

EXPOSE 22
CMD service nginx start && /usr/sbin/sshd -D -e
