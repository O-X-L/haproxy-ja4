#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

FILE_CRT='/tmp/haproxy.pem'
FILE_SCRIPT='/tmp/haproxy_ja4.lua'
FILE_HTML='/tmp/index.html'
FILE_MAP='/tmp/haproxy_ja4.map'

cd ..

FILE_MAP_SRC="$(pwd)/ja4.map"

if ! [ -f "$FILE_CRT" ]
then
  echo '### GENERATING CERT ###'
  openssl req -x509 -newkey rsa:4096 -sha256 -nodes -subj "/CN=HAProxy JA4 Test" -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" -keyout /tmp/haproxy.key.pem -out /tmp/haproxy.crt.pem -days 30
  cat /tmp/haproxy.crt.pem /tmp/haproxy.key.pem > "$FILE_CRT"
fi
if ! [ -L "$FILE_SCRIPT" ]
then
  echo '### LINKING SCRIPT ###'
  ln -s "$(pwd)/ja4.lua" "$FILE_SCRIPT"
fi
if ! [ -L "$FILE_HTML" ]
then
  echo '### LINKING HTML ###'
  ln -s "$(pwd)/test/index.html" "$FILE_HTML"
fi
if ! [ -L "$FILE_MAP" ]
then
  echo '### BUILDING MAP ###'
  if ! [ -f "$FILE_MAP_SRC" ]
  then
    curl -s https://ja4db.com/api/read/ -o ja4+_db.json
    python3 ja4db-to-map.py
  fi
  ln -s "$(pwd)/ja4.map" "$FILE_MAP"
fi

echo '### RUNNING ###'
haproxy -W -f test/haproxy_example.cfg
