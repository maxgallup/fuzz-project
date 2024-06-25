FROM ubuntu:18.04

USER root

RUN apt-get update

RUN apt-get -y install build-essential gnupg2 wget ca-certificates apt-transport-https autoconf automake cmake dpkg-dev file make patch libc6-dev curl vim tmux python3

RUN apt-get -y install clang-6.0

RUN apt-get -y install ruby-full

RUN apt-get -y install sudo

WORKDIR /home/dev/

COPY . .

RUN useradd dev -u 1000 -m -s /bin/bash && \
	echo "dev ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN chown -R dev:dev *

USER dev
