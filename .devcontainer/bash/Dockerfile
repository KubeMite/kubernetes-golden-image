FROM debian:13

RUN apt update && \
    apt install -y --no-install-recommends \
    bash \
    bash-completion \
    less \
    man-db \
    manpages \
    manpages-dev \
    linux-doc \
    shellcheck \
    shfmt && \
    rm -rf /var/lib/apt/lists/*
