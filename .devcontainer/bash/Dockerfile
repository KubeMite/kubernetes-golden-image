FROM debian:13

RUN apt update && \
    apt install -y --no-install-recommends \
    bash=5.2.37-2+b8 \
    bash-completion=1:2.16.0-7 \
    locales=2.41-12+deb13u2 \
    ca-certificates=20250419 \
    less=668-1 \
    linux-doc=6.12.74-2 \
    man-db=2.13.1-1 \
    manpages=6.9.1-1 \
    manpages-dev=6.9.1-1 \
    shellcheck=0.10.0-1 \
    shfmt=3.8.0-1+b8 && \
    rm -rf /var/lib/apt/lists/*
RUN sed -i 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen
RUN echo 'source /etc/bash_completion' >> ~/.bashrc
