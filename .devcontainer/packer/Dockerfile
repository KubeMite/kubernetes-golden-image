FROM hashicorp/packer:full-1.15.0


RUN apk add --no-cache \
    bash-completion=~2 \
    git-bash-completion=~2 \
    curl=~8 \
    jq=~1 \
    unzip=~6 \
    shadow=~4 && \
    rm -rf /var/cache/apk/*

# Set bash as shell
SHELL ["/bin/bash", "-c"]
RUN chsh -s /bin/bash root

WORKDIR /
# Install Bitwarden Secret Manager
COPY bws-setup.sh bws-setup.sh
RUN ./bws-setup.sh && rm bws-setup.sh
