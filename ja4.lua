-- Source: https://github.com/O-X-L/haproxy-ja4
-- Copyright (C) 2024 Rath Pascal
-- License: MIT
-- Algorithm License: BSD 3-Clause

-- JA4
-- see: https://github.com/FoxIO-LLC/ja4 | https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md#tls-and-dtls-version
-- config:
--   register: lua-load /etc/haproxy/lua/ja4.lua (in global)
--   run: http-request lua.fingerprint_ja4
--   log: http-request capture var(txn.fingerprint_ja4) len 36
--   acl: var(txn.fingerprint_ja4) -m str t13d1517h2_8daaf6152771_b0da82dd1658

local DTLS_1 = 65279
local DTLS_2 = 65277
local DTLS_3 = 65276
local TLS_VERSIONS = {}
TLS_VERSIONS[DTLS_3] = 'd3'
TLS_VERSIONS[DTLS_2] = 'd2'
TLS_VERSIONS[DTLS_1] = 'd1'
TLS_VERSIONS[772] = '13'
TLS_VERSIONS[771] = '12'
TLS_VERSIONS[770] = '11'
TLS_VERSIONS[769] = '10'
TLS_VERSIONS[768] = 's3'
TLS_VERSIONS[2] = 's2'

local function split_string(str, delimiter)
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

local function remove_from_table(tbl, val)
    for i,v in pairs(tbl) do
        if (v == val) then
            table.remove(tbl,i)
            break
        end
    end
end

function starts_with(value, start)
    return type(value) == "string" and type(start) == "string" and string.sub(value, 1, 1) == start
end

local function tls_protocol(txn)
    local v = txn.f:ssl_fc_protocol_hello_id()
    if (v == DTLS1 or v == DTLS_2 or v == DTLS_3) then
        return 'd'
    elseif (starts_with(txn.f:req_ver(), '3')) then
        return 'q'
    else
        return 't'
    end
end

local function tls_version(txn)
    local n

    -- get highest value from supported_versions extension
    local vers_bin = txn.f:ssl_fc_supported_versions_bin(1)
    if (vers_bin and #vers_bin >= 2) then
        local max_vers_bin = 0

        for i = 1, #vers_bin, 2 do
            local valid, current_vers_bin = pcall(string.unpack, '>I2', vers_bin, i)
            if (valid and current_vers_bin > max_vers_bin) then
                max_vers_bin = current_vers_bin
            end
        end

        n = TLS_VERSIONS[max_vers_bin]
    end

    if (not n) then
        n = TLS_VERSIONS[txn.f:ssl_fc_protocol_hello_id()]
    end

    return n or '00'
end

local function sni_is_set(txn)
    if (txn.f:ssl_fc_has_sni()) then
        return 'd'
    else
        return 'i'
    end
end

local function bin_list_length(txn, func)
    local bin_data = func(txn.f, 1)
    if (not bin_data) then
        return '00'
    end
    local items = split_string(txn.c:be2dec(bin_data, '-', 2), '-')
    return string.format('%02d', math.min(#items, 99))
end

local function is_alphanumeric(char)
    return string.match(char, '%a') or string.match(char, '%d')
end

local function alpn(txn)
    local a = txn.f:ssl_fc_alpn()

    if (not a or a == '') then
        return '00'
    end

    local fc = string.sub(a, 1, 1)
    local lc = string.sub(a, -1)

    if (not is_alphanumeric(fc) or not is_alphanumeric(lc)) then
        fc = string.format('%x', string.byte(fc)):sub(1, 1)
        lc = string.format('%x', string.byte(lc, #lc)):sub(-1)
    end

    return fc .. lc
end

local function ciphers_sorted(txn)
    local c = split_string(string.lower(txn.c:be2hex(txn.f:ssl_fc_cipherlist_bin(1), '-', 2)), '-')
    table.sort(c)
    return c
end

local function extensions_sorted(txn)
    local e = split_string(string.lower(txn.c:be2hex(txn.f:ssl_fc_extlist_bin(1), '-', 2)), '-')

    -- see: https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py#L109
    remove_from_table(e, '0000')
    remove_from_table(e, '0010')
    table.sort(e)
    return e
end

local function signature_algorithms(txn)
    -- https://github.com/FoxIO-LLC/ja4/blob/main/python/common.py#L147
    return split_string(string.lower(txn.c:be2hex(txn.f:ssl_fc_sigalgs_bin(1), '-', 2)), '-')
end

local function extensions_signature_merged(txn)
    -- see: https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py#L223
    local ext_sorted = extensions_sorted(txn)
    local ext_pretty = table.concat(ext_sorted, ',')
    local algos = signature_algorithms(txn)
    if (#algos == 0) then
        return ext_pretty
    else
        return ext_pretty .. '_' .. table.concat(algos, ',')
    end
end

local function truncated_sha256(txn, value)
    if (#value == 0) then
        return '000000000000'
    else
        return string.sub(string.lower(txn.c:hex(txn.c:digest(value, 'sha256'))), 1, 12)
    end
end

function fingerprint_ja4(txn)
    local p1 = tls_protocol(txn)
    local p2 = tls_version(txn)
    local p3 = sni_is_set(txn)
    local p4 = bin_list_length(txn, txn.f.ssl_fc_cipherlist_bin)
    local p5 = bin_list_length(txn, txn.f.ssl_fc_extlist_bin)
    local p6 = alpn(txn)

    local p7_sorted = ciphers_sorted(txn)
    local p7_pretty = table.concat(p7_sorted, ',')
    local p7 = truncated_sha256(txn, p7_pretty)

    local p8_pretty = extensions_signature_merged(txn)
    local p8 = truncated_sha256(txn, p8_pretty)

    txn:set_var('txn.fingerprint_ja4_raw', p1 .. '_' .. p2 .. '_' .. p3 .. '_' .. p4 .. '_' .. p5 .. '_' .. p6 .. '_' .. p7_pretty .. '_' .. p8_pretty)
    txn:set_var('txn.fingerprint_ja4', p1 .. p2 .. p3 .. p4 .. p5 .. p6 .. '_' .. p7 .. '_' .. p8)
end

core.register_action('fingerprint_ja4', {'tcp-req', 'http-req'}, fingerprint_ja4)
