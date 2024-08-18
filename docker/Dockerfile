ARG HAPROXY_VERSION=3.0
FROM alpine:latest

RUN apk --no-cache add curl python3 openssl
ADD ../ja4db-to-map.py .
RUN curl -s https://raw.githubusercontent.com/Egor-Skriptunoff/pure_lua_SHA/master/sha2.lua -o sha2.lua && \
    curl -s https://ja4db.com/api/read/ -o ja4+_db.json && \
    python3 ja4db-to-map.py
RUN openssl req -x509 -newkey rsa:4096 -sha256 -nodes -subj "/CN=HAProxy JA4 Test" \
    -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" -keyout haproxy.key.pem \
    -out haproxy.crt.pem -days 30 && \
    cat haproxy.crt.pem haproxy.key.pem > haproxy.pem

FROM haproxy:${HAPROXY_VERSION}
COPY --from=0 sha2.lua sha2.lua
COPY --from=0  ja4.map /tmp/haproxy_ja4.map
COPY --from=0  haproxy.pem /tmp/haproxy.pem
ADD docker/index.html /tmp/index.html

EXPOSE 6969
