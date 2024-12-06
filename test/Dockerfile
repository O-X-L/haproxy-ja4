FROM alpine:latest
ENV HAPROXY_SRC_URL https://github.com/haproxy/haproxy/archive/refs/heads

LABEL MAINTAINER Rath Pascal <rath@oxl.at>

# base source: https://github.com/haproxytech/haproxy-docker-alpine

ARG HAPROXY_BRANCH

ENV HAPROXY_BRANCH="${HAPROXY_BRANCH:-master}"

LABEL DEVELOPMENT BUILD

ENV HAPROXY_UID haproxy
ENV HAPROXY_GID haproxy

RUN test -n "$HAPROXY_BRANCH"

RUN apk add --no-cache ca-certificates jemalloc && \
    apk add --no-cache --virtual build-deps gcc libc-dev zip \
    linux-headers lua5.4-dev make openssl openssl-dev pcre2-dev tar \
    zlib-dev curl shadow jemalloc-dev && \
    curl -sfSL "${HAPROXY_SRC_URL}/${HAPROXY_BRANCH}.zip" -o haproxy.tar.gz && \
    groupadd "$HAPROXY_GID" && \
    useradd -g "$HAPROXY_GID" "$HAPROXY_UID" && \
    mkdir -p /tmp/haproxy && \
    unzip haproxy.tar.gz -d /tmp/haproxy && \
    mv /tmp/haproxy/haproxy-${HAPROXY_BRANCH}/* /tmp/haproxy && \
    rm -f haproxy.tar.gz && \
    make -C /tmp/haproxy -j"$(nproc)" TARGET=linux-musl CPU=generic USE_PCRE2=1 USE_PCRE2_JIT=1 \
                            USE_TFO=1 USE_LINUX_TPROXY=1 USE_GETADDRINFO=1 \
                            USE_LUA=1 LUA_LIB=/usr/lib/lua5.4 LUA_INC=/usr/include/lua5.4 \
                            USE_PROMEX=1 USE_SLZ=1 \
                            USE_OPENSSL=1 USE_PTHREAD_EMULATION=1 \
                            USE_QUIC=1 USE_QUIC_OPENSSL_COMPAT=1 \
                            ADDLIB=-ljemalloc \
                            all && \
    make -C /tmp/haproxy TARGET=linux2628 install-bin install-man && \
    ln -s /usr/local/sbin/haproxy /usr/sbin/haproxy && \
    mkdir -p /var/lib/haproxy && \
    chown "$HAPROXY_UID:$HAPROXY_GID" /var/lib/haproxy && \
    mkdir -p /usr/local/etc/haproxy && \
    ln -s /usr/local/etc/haproxy /etc/haproxy && \
    cp -R /tmp/haproxy/examples/errorfiles /usr/local/etc/haproxy/errors && \
    rm -rf /tmp/haproxy && \
    apk del build-deps && \
    apk add --no-cache openssl zlib lua5.4-libs pcre2 curl python3 && \
    rm -f /var/cache/apk/*

ADD ../ja4db-dedupe.py .
ADD ../ja4db-to-map.py .
RUN curl -s https://raw.githubusercontent.com/Egor-Skriptunoff/pure_lua_SHA/master/sha2.lua -o sha2.lua && \
    curl -s https://ja4db.com/api/read/ -o ja4db.json && \
    python3 ja4db-dedupe.py && \
    python3 ja4db-to-map.py
RUN openssl req -x509 -newkey rsa:4096 -sha256 -nodes -subj "/CN=HAProxy JA4 Test" \
    -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" -keyout haproxy.key.pem \
    -out haproxy.crt.pem -days 30 && \
    cat haproxy.crt.pem haproxy.key.pem > haproxy.pem

FROM alpine:latest
ENV HAPROXY_DOCKER_SRC_URL https://raw.githubusercontent.com/haproxytech/haproxy-docker-alpine/main/3.1/
RUN apk add --no-cache openssl zlib lua5.4-libs pcre2 jemalloc
ADD --chmod=755 "${HAPROXY_DOCKER_SRC_URL}/docker-entrypoint.sh" '/docker-entrypoint.sh'
ADD --chmod=644 "${HAPROXY_DOCKER_SRC_URL}/haproxy.cfg" '/usr/local/etc/haproxy/haproxy.cfg'
COPY --from=0 /usr/local/sbin/haproxy /usr/local/sbin/haproxy
COPY --from=0 ja4.map /tmp/haproxy_ja4.map
COPY --from=0 haproxy.pem /tmp/haproxy.pem
ADD test/index.html /tmp/index.html

EXPOSE 6969
STOPSIGNAL SIGUSR1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"]
