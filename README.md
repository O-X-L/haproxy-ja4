# HAProxy - JA4 TLS Client-Fingerprint - Lua Plugin

**WARNING: This plugin is still in early development! DO NOT USE IN PRODUCTION!**

## Intro

About JA4:

* [HAProxy Lua Plugin (JA4H)](https://github.com/O-X-L/haproxy-ja4h)
* [JA4 Suite](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)
* [JA4 TLS details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
* [FoxIO Repository](https://github.com/FoxIO-LLC/ja4)
* [Cloudflare Blog](https://blog.cloudflare.com/ja4-signals)
* [FoxIO Blog](https://blog.foxio.io/ja4%2B-network-fingerprinting)
* [FoxIO JA4 Database](https://ja4db.com/)

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
> t13d1517h2_8daaf6152771_b0da82dd1658 Chromium_Browser
> t13d1517h2_8daaf6152771_b1ff8ab2d16f Chromium_Browser
> t13d190900_9dc949149365_97f8aa674fd9 Sliver_Agent
> t13d190900_9dc949149365_97f8aa674fd9 Sliver_Agent
> t13d1516h2_8daaf6152771_02713d6af862 Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64)_AppleWebKit/537.36_(KHTML,_like_Gecko)_Chrome/125.0.0.0_Safari/537.36
```

You can enable lookups like this: `http-request set-var(txn.fingerprint_app) var(txn.fingerprint_ja4),map_beg(/tmp/haproxy_ja4.map)`

And log the results like this: `http-request capture var(txn.fingerprint_app) len 200`


----

## Contribute

If you have:

* Found an issue/bug - please [report it](https://github.com/O-X-L/haproxy-ja4/issues/new)
* Have an idea on how to improve it - [feel free to start a discussion](https://github.com/O-X-L/haproxy-ja4/discussions/new/choose)
* PRs are welcome

### Issues

* Have not yet been able to implement the signature algorithm fetching method ([src1](https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py#L147), [src2](https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py#L215))

### Testing

* Create snakeoil certificate:

  ```bash
  openssl req -x509 -newkey rsa:4096 -sha256 -nodes -subj "/CN=HAProxy JA4 Test" -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" -keyout /tmp/haproxy.key.pem -out /tmp/haproxy.crt.pem -days 30
  cat /tmp/haproxy.crt.pem /tmp/haproxy.key.pem > /tmp/haproxy.pem
  ```

* Link the LUA script: `ln -s $(pwd)/ja4.lua /tmp/haproxy_ja4.lua`
* Link the DB map: `ln -s $(pwd)/ja4.map /tmp/haproxy_ja4.map`
* You can run the `haproxy_example.cfg` manually like this: `haproxy -W -f haproxy_example.cfg`
* Access the test website: https://localhost:6969/


```bash
127.0.0.1:44480 [16/Aug/2024:16:46:56.981] test_ja4~ test_ja4/<NOSRV> 0/-1/-1/-1/0 200 49 - - PR-- 1/1/0/0/0 0/0 {t12d1715h2_002f,0035,009c,009d,1301,1302,1303,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,001c,0022,0029,002b,002d,0033,fe0d,ff01|t12d1715h2_4a3d28116287_c114573b7948|} "GET https://localhost:6969/ HTTP/2.0"
```
