FROM debian:13

# Configure bash completion
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash-completion=1:2.16.0-7 \
    locales=2.41-12+deb13u2 \
    ca-certificates=20250419 \
    && rm -rf /var/lib/apt/lists/*
RUN sed -i 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen
RUN echo 'source /etc/bash_completion' >> ~/.bashrc