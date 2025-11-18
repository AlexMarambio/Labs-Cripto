FROM ubuntu:22.10
RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://old-releases.ubuntu.com/ubuntu/|g' /etc/apt/sources.list \
    && sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu/|g' /etc/apt/sources.list
RUN apt-get update && apt-get install -y openssh-client openssh-server tcpdump
RUN useradd -m -s /bin/bash prueba && echo "prueba:prueba" | chpasswd
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
CMD ["/bin/bash"]
