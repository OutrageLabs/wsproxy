FROM alpine:3.20

RUN apk add --no-cache openssh-server && \
    ssh-keygen -A && \
    adduser -D -s /bin/sh testuser && \
    echo "testuser:testpass" | chpasswd && \
    mkdir -p /home/testuser/.ssh && \
    chown -R testuser:testuser /home/testuser/.ssh && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    echo "AllowAgentForwarding yes" >> /etc/ssh/sshd_config && \
    echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config && \
    echo "Subsystem sftp /usr/lib/ssh/sftp-server" >> /etc/ssh/sshd_config

# Create test files for SFTP
RUN mkdir -p /home/testuser/testdir && \
    echo "hello world" > /home/testuser/testdir/test.txt && \
    chown -R testuser:testuser /home/testuser/testdir

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
