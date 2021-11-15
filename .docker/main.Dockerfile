ARG VERSION=unstable
ARG DEBIAN_FRONTEND=noninteractive

FROM greenbone/gvm-libs:${VERSION} as builder

# Install Debian core dependencies required for building gvm with PostgreSQL
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libglib2.0-dev \
    libgnutls28-dev \
    libxml2-dev \
    libssh-gcrypt-dev \
    libmicrohttpd-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . /source
WORKDIR /source

RUN mkdir /build && \
    mkdir /install && \
    cd /build && \
    cmake -DCMAKE_BUILD_TYPE=Release /source && \
    make DESTDIR=/install install

FROM greenbone/gvm-libs:${VERSION}

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libmicrohttpd12 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install/ /

# create web directory where GSA should be placed
RUN mkdir -p /usr/local/share/gvm/gsad/web

ENTRYPOINT [ "gsad" ]
CMD ["-f", "--http-only"]