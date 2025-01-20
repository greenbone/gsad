#/bin/sh
# This script installs dependencies of gsad assuming that gvm-libs is already installed.
set -e

apt-get update && \
apt-get install -y --no-install-recommends  --no-install-suggests \
    build-essential \
    cmake \
    gcc \
    git \
    libgcrypt-dev \
    libglib2.0-dev \
    libgnutls28-dev \
    libmicrohttpd-dev \
    libssh-dev \
    libxml2-dev \
    pkg-config && \
    rm -rf /var/lib/apt/lists/*
