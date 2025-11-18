FROM ubuntu:16.10

RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://old-releases.ubuntu.com/ubuntu/|g' /etc/apt/sources.list \
    && sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu/|g' /etc/apt/sources.list

RUN apt-get update && apt-get install -y openssh-client

CMD ["/bin/bash"]
