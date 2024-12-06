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

DEBUG = False
# see: https://www.haproxy.com/blog/introduction-to-haproxy-maps
#   'Empty lines and extra whitespace between words are ignored'
WHITESPACE_REPLACE = '_'

if not Path('ja4_dedupe.json').is_file():
    shell('python3 ja4db-dedupe.py')

with open('ja4_dedupe.json', 'r', encoding='utf-8') as db_file:
    db = json_loads(db_file.read())

with open('ja4.map', 'w', encoding='utf-8') as map_file:
    map_file.write('# SOURCE: https://ja4db.com/\n\n')
    map_file.write('\n'.join([
        f"{fp} {client.replace(' ', WHITESPACE_REPLACE)}"
        for fp, client in db.items()
    ]))
