#!/usr/bin/env python3

# Source: https://github.com/O-X-L/haproxy-ja4
# Copyright (C) 2024 Rath Pascal
# License: MIT

# download raw db:
#   curl -s https://ja4db.com/api/read/ -o ja4db.json
# generate a deduplicated db:
#   python3 ja4db-dedupe.py

from pathlib import Path
from os import system as shell
from json import loads as json_loads

HEADERS = ['fingerprint', 'client']
SEPARATOR = ','

if not Path('ja4_dedupe.json').is_file():
    shell('python3 ja4db-dedupe.py')

with open('ja4_dedupe.json', 'r', encoding='utf-8') as db_file:
    db = json_loads(db_file.read())

with open('ja4.csv', 'w', encoding='utf-8') as csv_file:
    csv_file.write(SEPARATOR.join(HEADERS) + '\n')
    csv_file.write('\n'.join([
        f"{fp}{SEPARATOR}{client.replace(SEPARATOR, '')}"
        for fp, client in db.items()
    ]))
