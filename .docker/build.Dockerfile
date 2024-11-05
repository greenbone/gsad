# Define ARG we use through the build
ARG GVM_LIBS_VERSION=oldstable

# We want gvm-libs to be ready so we use the build docker image of gvm-libs
FROM registry.community.greenbone.net/community/gvm-libs:${GVM_LIBS_VERSION}

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /source

# Install Debian core dependencies required for building gvm with PostgreSQL
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    gcc \
    pkg-config \
    libglib2.0-dev \
    libgnutls28-dev \
    libxml2-dev \
    libssh-gcrypt-dev \
    libmicrohttpd-dev \
    libcgreen1-dev && \
    rm -rf /var/lib/apt/lists/*

RUN ldconfig
