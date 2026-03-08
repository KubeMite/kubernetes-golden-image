FROM debian:13

RUN apt update && \
    apt install -y --no-install-recommends \
    bash \
    bash-completion \
    ca-certificates \
    less \
    linux-doc \
    man-db \
    manpages \
    manpages-dev \
    shellcheck \
    shfmt && \
    rm -rf /var/lib/apt/lists/*
