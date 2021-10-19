# Dockerfile for gsad-$VERSION-$COMPILER-build

# Define ARG we use through the build
ARG VERSION=master
ARG BUILD_TYPE=Debug
ARG COMPILER=gcc

FROM greenbone/gsad-$VERSION-$COMPILER-testing

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

COPY . /usr/local/src
WORKDIR /usr/local/src

# clone and install gsad
RUN mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make install
