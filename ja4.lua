-- Source: https://github.com/O-X-L/haproxy-ja4
-- Copyright (C) 2024 Rath Pascal
-- License: MIT

-- JA4
-- see: https://github.com/FoxIO-LLC/ja4
-- config:
--   register: lua-load /etc/haproxy/lua/ja4.lua (in global)
--   run: http-request lua.fingerprint_ja4
--   log: http-request capture var(txn.fingerprint_ja4) len 36
--   acl: var(txn.fingerprint_ja4) -m str t13d1517h2_8daaf6152771_b0da82dd1658

local sha = require('sha2')
-- see: https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py#L24
local GREASE_TABLE = {}
GREASE_TABLE['0x0a0a'] = true
GREASE_TABLE['0x1a1a'] = true
GREASE_TABLE['0x2a2a'] = true
GREASE_TABLE['0x3a3a'] = true
GREASE_TABLE['0x4a4a'] = true
GREASE_TABLE['0x5a5a'] = true
GREASE_TABLE['0x6a6a'] = true
GREASE_TABLE['0x7a7a'] = true
GREASE_TABLE['0x8a8a'] = true
GREASE_TABLE['0x9a9a'] = true
GREASE_TABLE['0xaaaa'] = true
GREASE_TABLE['0xbaba'] = true
GREASE_TABLE['0xcaca'] = true
GREASE_TABLE['0xdada'] = true
GREASE_TABLE['0xeaea'] = true
GREASE_TABLE['0xfafa'] = true

local TLS_VERSIONS = {}
TLS_VERSIONS[65276] = 'd3'
TLS_VERSIONS[65277] = 'd2'
TLS_VERSIONS[65279] = 'd1'
TLS_VERSIONS[772] = '13'
TLS_VERSIONS[771] = '12'
TLS_VERSIONS[770] = '11'
TLS_VERSIONS[769] = '10'
TLS_VERSIONS[768] = 's3'
TLS_VERSIONS[2] = 's2'

function split_string(str, delimiter)
    local result = {}
    local from  = 1
    local delim_from, delim_to = string.find(str, delimiter, from)
    while delim_from do
        table.insert(result, string.sub(str, from , delim_from-1))
        from  = delim_to + 1
        delim_from, delim_to = string.find(str, delimiter, from)
    end
    table.insert(result, string.sub(str, from))
    return result
end

function remove_from_table(tbl, val)
    for i,v in pairs(tbl) do
        if v == val then
            table.remove(tbl,i)
            break
        end
    end
end

function table_length(tbl)
    local count = 0
    for _ in pairs(tbl) do count = count + 1 end
    return count
end

function is_grease_value(value)
    return GREASE_TABLE[value] ~= nil
end

function tls_version(txn)
    local v = txn.f:ssl_fc_protocol_hello_id()
    local n = TLS_VERSIONS[v]
    if (n==nil)
    then
        return ''
    else
        return n
    end
end

function sni_is_set()
    if (ssl_fc_sni=='')
    then
        return 'i'
    else
        return 'd'
    end
end

function remove_grease(tbl)
    for i,v in pairs(tbl) do
        if is_grease_value(v) then
            table.remove(tbl,i)
        end
    end
end

function cipher_count(txn)
    local e = split_string(tostring(txn.c:be2dec(txn.f:ssl_fc_cipherlist_bin(1),"-",2)), "-")
    remove_grease(e)
    local c = table_length(e)
    if (c>99)
    then
        return '99'
    else
        return tostring(c)
    end
end

function extension_count(txn)
    local e = split_string(tostring(txn.c:be2dec(txn.f:ssl_fc_extlist_bin(1),"-",2)), "-")
    remove_grease(e)
    local c = table_length(e)
    if (c>99)
    then
        return '99'
    else
        return tostring(c)
    end
end

function alpn(txn)
    local a = txn.f:ssl_fc_alpn()
    if (a=='')
    then
        return '00'
    else
        return a
    end
end

function ciphers_sorted(txn)
    local c1 = string.lower(string.lower(tostring(txn.c:be2hex(txn.f:ssl_fc_cipherlist_bin(1),"-",2))))
    local c2 = split_string(c1, "-")
    remove_grease(c2)
    table.sort(c2)
    return c2
end

function extensions_sorted(txn)
    local e1 = string.lower(tostring(txn.c:be2hex(txn.f:ssl_fc_extlist_bin(1),"-",2)))
    local e2 = split_string(e1, "-")
    remove_grease(e2)
    -- see: https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py#L109
    remove_from_table(e2, '0000')
    remove_from_table(e2, '0010')
    table.sort(e2)
    return e2
end

function signature_algo_sorted(txn)
    -- todo: https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py#L147
    --       (https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py#L215)
    local algos = {}
    return algos
end

function extensions_signature_merged(txn)
    -- see: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py#L223
    local ext_sorted = extensions_sorted(txn)
    local ext_pretty = table.concat(ext_sorted, ",")
    local sig_sorted = signature_algo_sorted(txn)
    if (table_length(sig_sorted)==0)
    then
        return ext_pretty
    else
        return ext_pretty .. '_' .. table.concat(sig_sorted, ",")
    end
end

function truncated_sha256(value)
    return string.sub(sha.sha256(value), 1, 12)
end

function fingerprint_ja4(txn)
    local p1 = 't'  -- todo: lookup if quic/tcp
    local p2 = tls_version(txn)
    local p3 = sni_is_set()
    local p4 = cipher_count(txn)
    local p5 = extension_count(txn)
    local p6 = alpn(txn)

    local test = tostring(txn.c:be2hex(txn.f:ssl_fc_cipherlist_bin(1),"-",2))

    local p7_sorted = ciphers_sorted(txn)
    local p7_pretty = table.concat(p7_sorted, ",")
    local p7 = truncated_sha256(table.concat(p7_sorted, ""))

    local p8_pretty = extensions_signature_merged(txn)
    local p8 = truncated_sha256(p8_pretty)

    txn:set_var('txn.fingerprint_ja4_raw', p1 .. p2 .. p3 .. p4 .. p5 .. p6 .. '_' .. p7_pretty .. '_' .. p8_pretty)
    txn:set_var('txn.fingerprint_ja4', p1 .. p2 .. p3 .. p4 .. p5 .. p6 .. '_' .. p7 .. '_' .. p8)
end

core.register_action('fingerprint_ja4', {'tcp-req', 'http-req'}, fingerprint_ja4)
