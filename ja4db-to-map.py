# Source: https://github.com/O-X-L/haproxy-ja4
# Copyright (C) 2024 Rath Pascal
# License: MIT

from json import loads as json_loads

DEBUG = False
# see: https://www.haproxy.com/blog/introduction-to-haproxy-maps 'Empty lines and extra whitespace between words are ignored'
WHITESPACE_REPLACE = '_'

CLIENT_KEYS = ['user_agent_string', 'application', 'notes']


def get_client(_entry: dict):
    for k in CLIENT_KEYS:
        if _entry[k] is not None:
            return _entry[k].strip()

    return None


processed = []

with open('ja4+_db.json', 'r', encoding='utf-8') as db_file:
    db_full = json_loads(db_file.read())
    db_kv = []
    for entry in db_full:
        if DEBUG:
            print(entry)

        if entry['ja4_fingerprint'] is not None:
            client = get_client(entry)
            if client not in [None, ''] and entry['ja4_fingerprint'] not in processed:
                processed.append(entry['ja4_fingerprint'])
                db_kv.append(f"{entry['ja4_fingerprint']} {client.replace(' ', WHITESPACE_REPLACE)}")

with open('ja4.map', 'w', encoding='utf-8') as map_file:
    map_file.write('# SOURCE: https://ja4db.com/\n\n' + '\n'.join(db_kv))
