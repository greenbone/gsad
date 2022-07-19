ARG VERSION=oldstable
ARG DEBIAN_FRONTEND=noninteractive

FROM greenbone/gsad-build:$VERSION as build

# Install
COPY . /source
RUN cmake -DCMAKE_BUILD_TYPE=Release -B/build /source
RUN DESTDIR=/install cmake --build /build -- install


FROM greenbone/gvm-libs:$VERSION

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gosu \
    libmicrohttpd12 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /install/ /
COPY .docker/gsad_log.conf /etc/gvm/
COPY .docker/start-gsad.sh /usr/local/bin/start-gsad
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

RUN addgroup --gid 1001 --system gsad && \
    adduser --no-create-home --shell /bin/false --disabled-password \
    --uid 1001 --system --group gsad

# create web directory where GSA should be placed and runtime files directories
RUN mkdir -p /usr/local/share/gvm/gsad/web /run/gsad /var/log/gvm \
    && chown -R gsad:gsad /run/gsad /var/log/gvm \
    && chmod 755 /usr/local/bin/entrypoint \
    && chmod 755 /usr/local/bin/start-gsad

ENTRYPOINT [ "/usr/local/bin/entrypoint" ]

CMD ["/usr/local/bin/start-gsad"]
