# HAProxy - JA4 TLS Client-Fingerprint - Lua Plugin

## WARNING: Not production ready

This plugin depends on [HAProxy Features that will be release in version 3.1](https://github.com/haproxy/haproxy/issues/2495)!

If these features are not yet available in your version - it will fail with the error `attempt to call a nil value (method 'ssl_fc_supported_versions_bin')`

----

## Intro

About JA4:

* [JA4 TLS details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
* [Cloudflare Blog](https://blog.cloudflare.com/ja4-signals)
* [FoxIO Blog](https://blog.foxio.io/ja4%2B-network-fingerprinting)
* [FoxIO JA4 Database](https://ja4db.com/)
* [JA4 Suite](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)

About JA3:
* [HAProxy Lua Plugin (JA3N)](https://github.com/O-X-L/haproxy-ja3n)
* [Salesforce Repository](https://github.com/salesforce/ja3)
* [HAProxy Enterprise JA3 Fingerprint](https://customer-docs.haproxy.com/bot-management/client-fingerprinting/tls-fingerprint/)
* [Why JA3 broke => JA3N](https://github.com/salesforce/ja3/issues/88)

----

## Usage

* Add the LUA script `ja4.lua` to your system

## Config

* Enable SSL/TLS capture with the global setting [tune.ssl.capture-buffer-size 128](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/#tune.ssl.capture-buffer-size)
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

# examples:
> t13d1517h2_8daaf6152771_b0da82dd1658 Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36_(KHTML,_like_Gecko)_Chrome/125.0.0.0_Safari/537.36
> t13d1516h2_8daaf6152771_02713d6af862 Chromium_Browser
```

You can enable lookups like this: `http-request set-var(txn.fingerprint_app) var(txn.fingerprint_ja4),map(/tmp/haproxy_ja4.map)`

And log the results like this: `http-request capture var(txn.fingerprint_app) len 200`

----

## Contribute

If you have:

* Found an issue/bug - please [report it](https://github.com/O-X-L/haproxy-ja4/issues/new)
* Have an idea on how to improve it - [feel free to start a discussion](https://github.com/O-X-L/haproxy-ja4/discussions/new/choose)
* PRs are welcome

Please [read the JA4 TLS details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)!

### Testing

Example:
```
FINGERPRINT
t13d1713h2_5b57614c22b0_748f4c70de1c

APP FROM DB
Mozilla/5.0_(Android_14;_Mobile;_rv:126.0)_Gecko/126.0_Firefox/126.0

DEBUG
raw fingerprint: t_13_d_17_13_h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,001c,0022,002b,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201 
```

#### Docker

If you prefer to use Docker, the manual steps can be skipped.
Run the docker container from the project root and access https://localhost:6969

```bash
docker compose -f test/docker-compose.yaml up --build --watch
```

`--watch` will automatically rebuild the container on changes

#### Local

**WARNING**: You need to run a version of HAProxy >=3.1 or `master` 

* Run: `bash test/run.sh`
* Access the test website: https://localhost:6969/

Exit with `CTRL+C`

