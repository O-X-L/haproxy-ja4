# HAProxy - JA4 TLS Client-Fingerprint - Lua Plugin

**WARNING: This plugin is still in early development! DO NOT USE IN PRODUCTION!**

## Intro

About JA4:

* [JA4 Suite](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)
* [JA4 TLS details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
* [FoxIO Repository](https://github.com/FoxIO-LLC/ja4)
* [Cloudflare Blog](https://blog.cloudflare.com/ja4-signals)
* [FoxIO Blog](https://blog.foxio.io/ja4%2B-network-fingerprinting)
* [FoxIO JA4 Database](https://ja4db.com/)
* [HAProxy Lua Plugin Draft (JA4H)](https://github.com/O-X-L/haproxy-ja4h)

About JA3:
* [HAProxy Lua Plugin (JA3N)](https://github.com/O-X-L/haproxy-ja3n)
* [Salesforce Repository](https://github.com/salesforce/ja3)
* [HAProxy Enterprise JA3 Fingerprint](https://customer-docs.haproxy.com/bot-management/client-fingerprinting/tls-fingerprint/)
* [JA3N](https://tlsfingerprint.io/norm_fp)

----

## Usage

* Add the LUA script `ja4.lua` and [sha2.lua](https://github.com/Egor-Skriptunoff/pure_lua_SHA) ([download](https://raw.githubusercontent.com/Egor-Skriptunoff/pure_lua_SHA/master/sha2.lua)) to your system

## Config

* Enable SSL/TLS capture with the global setting [tune.ssl.capture-buffer-size 96](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/#tune.ssl.capture-buffer-size)
* Load the LUA module with `lua-load /etc/haproxy/lua/ja4.lua`
* Execute the LUA script on HTTP requests: `http-request lua.fingerprint_ja4`
* Log the fingerprint: `http-request capture var(txn.fingerprint_ja4) len 36`

### JA4 Database

You can use [the DB to MAP script](https://github.com/O-X-L/haproxy-ja4/blob/latest/ja4db-to-map.py) to create a HAProxy Mapfile from the [FoxIO JA4-Database](https://ja4db.com/):

```bash
# download the DB in JSON format: https://ja4db.com/api/download/
# place it in the same directory as the script

# build the map-file
python3 ja4db-to-map.py

# check the output file
head ja4.map
> # SOURCE: https://ja4db.com/
> 
> t13d1517h2_8daaf6152771_b0da82dd1658 Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36_(KHTML,_like_Gecko)_Chrome/125.0.0.0_Safari/537.36
> t13d1516h2_8daaf6152771_02713d6af862 Chromium_Browser
> q13d0312h3_55b375c5d22e_06cda9e17597 Chromium_Browser
> t13d1517h2_8daaf6152771_b1ff8ab2d16f Chromium_Browser
> t13d190900_9dc949149365_97f8aa674fd9 Sliver_Agent
> t13d301200_1d37bd780c83_d339722ba4af http.rb/5.1.1_(Mastodon/4.2.9-stable+ff1;_+https://wien.rocks/)_Bot
> t13d0912h2_f91f431d341e_dc02626b439c Fedineko_(crabo/0.3.1;_+https://fedineko.org/about)
> t13d1714h2_5b57614c22b0_14788d8d241b Mozilla/5.0_(iPhone;_CPU_iPhone_OS_17_5_like_Mac_OS_X)_AppleWebKit/605.1.15_(KHTML,_like_Gecko)_CriOS/125.0.6422.80_Mobile/15E148_Safari/604.1
```

You can enable lookups like this: `http-request set-var(txn.fingerprint_app) var(txn.fingerprint_ja4),map(/tmp/haproxy_ja4.map)`

And log the results like this: `http-request capture var(txn.fingerprint_app) len 200`


----

## Contribute

If you have:

* Found an issue/bug - please [report it](https://github.com/O-X-L/haproxy-ja4/issues/new)
* Have an idea on how to improve it - [feel free to start a discussion](https://github.com/O-X-L/haproxy-ja4/discussions/new/choose)
* PRs are welcome

### Issues

* Have not yet been able to implement the signature algorithm fetching method ([src1](https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py#L147), [src2](https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py#L215))
* Usage of [ssl_fc_protocol](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/#7.3.4-ssl_fc_protocol) or 
  [ssl_fc_protocol_hello_id](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/#7.3.4-ssl_fc_protocol_hello_id) for part 2 of the fingerprint

### Testing

* Run: `bash test/test.sh`
* Access the test website: https://localhost:6969/

Exit with `CTRL+C`

#### Docker

If you prefer to use Docker, the manual steps can be skipped.
Run the docker container from the project root and access https://localhost:6969

```bash
docker compose -f test/docker-compose.yaml up --build --watch
```

`--watch` will automatically rebuild the container on changes
