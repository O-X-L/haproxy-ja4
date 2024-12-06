#!/usr/bin/env python3

# Source: https://github.com/O-X-L/haproxy-ja4
# Copyright (C) 2024 Rath Pascal
# License: MIT

# script used to create a list of only bot-related fingerprints

# download raw db:
#   curl -s https://ja4db.com/api/read/ -o ja4db.json

# pylint: disable=R0801

from re import sub as regex_replace
from json import loads as json_loads
from json import dumps as json_dumps

DEBUG = False
BOT_SCRIPT = [
    'golang', 'wget', 'curl', 'go-http-client', 'apache-httpclient', 'java', 'perl',
    'python', 'openssl', 'headless', 'cypress', 'mechanicalsoup', 'grpc-go', 'okhttp',
    'httpx', 'httpcore', 'aiohttp', 'httputil', 'urllib', 'guzzle', 'axios', 'ruby',
    'zend_http_client', 'wordpress', 'symfony', 'httpclient', 'cpp-httplib', 'ngrok',
    'malware', 'httprequest',
]
BOT_SCAN = [
    'scan', 'scanner', 'nessus', 'metasploit', 'zgrab', 'zmap', 'nmap', 'research',
]
BOT_CRAWL = [
    'bot', 'mastodon', 'https://', 'http://', 'whatsapp', 'twitter', 'facebook', 'chatgpt',
    'telegram', 'crawler', 'colly', 'phpcrawl', 'nutch', 'spider', 'scrapy', 'elinks',
    'imageVacuum', 'apify',
]
BOT_RANDOM = [
    'mozilla/4.', 'mozilla/3.', 'mozilla/2.', 'fidget-spinner-bot', 'test-bot', 'tiny-bot',
    'download', 'printer', 'router', 'camera', 'phillips hue', 'vpn', 'cisco',
]
BOT_SEARCH = BOT_SCRIPT
BOT_SEARCH.extend(BOT_SCAN)
BOT_SEARCH.extend(BOT_CRAWL)
BOT_SEARCH.extend(BOT_RANDOM)

CLIENT_KEYS = ['user_agent_string', 'application', 'notes', 'os']

bot_fp = {}
bot_fp_score = {}


def _get_client(_entry: dict) :
    for k in CLIENT_KEYS:
        if _entry[k] is not None:
            return _entry[k].strip()

    return None


with open('ja4db.json', 'r', encoding='utf-8') as db_file:
    db = json_loads(db_file.read())

for entry in db:
    fp = entry['ja4_fingerprint']
    if fp is None:
        continue

    fp = regex_replace(r'[^a-z0-9_]', '', fp)
    client = _get_client(entry)
    if client in [None, ''] or len(fp) != 36:
        continue

    clow = client.lower()

    bot = False
    for s in BOT_SEARCH:
        if clow.find(s) != -1:
            bot = True
            bot_fp[fp] = client
            break

    if fp not in bot_fp_score:
        bot_fp_score[fp] = 0

    bot_fp_score[fp] += 1 if bot else -1

if DEBUG:
    with open('ja4_bots_full.json', 'w', encoding='utf-8') as f:
        f.write(json_dumps(bot_fp_score, indent=4))

for fp, score in bot_fp_score.items():
    if score < 1:
        try:
            bot_fp.pop(fp)

        except KeyError:
            pass

with open('ja4_bots.json', 'w', encoding='utf-8') as f:
    f.write(json_dumps(bot_fp, indent=4))
