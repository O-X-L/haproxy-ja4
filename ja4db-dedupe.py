#!/usr/bin/env python3

# Source: https://github.com/O-X-L/haproxy-ja4
# Copyright (C) 2024 Rath Pascal
# License: MIT

# script used to de-duplicate the fingerprint-applications listed inside the ja4db
# it's not perfect, but better than only pulling a random one

# download raw db:
#   curl -s https://ja4db.com/api/read/ -o ja4db.json

from collections import Counter
from re import sub as regex_replace
from json import loads as json_loads
from json import dumps as json_dumps

DEBUG = False
DEDUPE_FACTOR = 5

CLIENT_KEYS = ['user_agent_string', 'application', 'notes', 'os']

processed = {}
processed_clients = {}


def _get_client(_entry: dict):
    for k in CLIENT_KEYS:
        if _entry[k] is not None:
            return _entry[k].strip()

    return None


def _client_split(c):
    c = c.replace('(', '').replace(')', '')
    out = []

    for _c in c.split(' '):
        out.extend(_c.split('/'))

    return out


with open('ja4db.json', 'r', encoding='utf-8') as db_file:
    db_full = json_loads(db_file.read())
    for entry in db_full:
        fp = entry['ja4_fingerprint']
        if fp is None:
            continue

        fp = regex_replace(r'[^a-z0-9_]', '', fp)
        client = _get_client(entry)
        if client in [None, ''] or len(fp) != 36:
            continue

        client_items = _client_split(client)

        if fp not in processed:
            processed[fp] = [client_items]
            processed_clients[fp] = client_items

        else:
            processed[fp].append(client_items)
            processed_clients[fp].extend(client_items)


fp_to_dedupe = {}
fp_to_dedupe2 = {}
for fp, entries in processed_clients.items():
    entry_cnt = len(processed[fp])
    min_occ = entry_cnt - round((entry_cnt / DEDUPE_FACTOR))
    fp_to_dedupe[fp] = {
        k: v for k, v in Counter(entries).items()
        if v >= min_occ and k.strip() != ''
    }
    dedupe_client = ' '.join(list(fp_to_dedupe[fp].keys()))
    if dedupe_client == '' or regex_replace(r'[0-9\.\s]', '', dedupe_client) == '':
        continue

    fp_to_dedupe2[fp] = dedupe_client

if DEBUG:
    with open('ja4_dedupe_full.json', 'w', encoding='utf-8') as f:
        f.write(json_dumps(fp_to_dedupe, indent=4))

with open('ja4_dedupe.json', 'w', encoding='utf-8') as f:
    f.write(json_dumps(fp_to_dedupe2, indent=4))
