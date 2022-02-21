ARG VERSION=stable
ARG DEBIAN_FRONTEND=noninteractive

FROM greenbone/gvmd-build:$VERSION as build

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

# Install
COPY . /source
RUN cmake -DCMAKE_BUILD_TYPE=Release -B/build /source
RUN DESTDIR=/install cmake --build /build -- install 


FROM greenbone/gvm-libs:$VERSION

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libmicrohttpd12 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install/ /
COPY .docker/gsad_log.conf /etc/gvm/
COPY .docker/start-gsad.sh /usr/local/bin/start-gsad

RUN addgroup --gid 1001 --system gsad && \
    adduser --no-create-home --shell /bin/false --disabled-password \
    --uid 1001 --system --group gsad

# create web directory where GSA should be placed and runtime files directories
RUN mkdir -p /usr/local/share/gvm/gsad/web /run/gsad /var/log/gvm \
    && chown -R gsad:gsad /run/gsad /var/log/gvm \
    && chmod 755 /usr/local/bin/start-gsad

USER gsad

CMD ["/usr/local/bin/start-gsad"]
