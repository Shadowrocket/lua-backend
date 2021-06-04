-- file: lua/trojan-http.lua

local http = require 'http'
local backend = require 'backend'
local network = require 'network'

local char = string.char
local byte = string.byte

local ADDRESS = backend.ADDRESS
local PROXY = backend.PROXY
local SUCCESS = backend.RESULT.SUCCESS

local ctx_uuid = backend.get_uuid
local ctx_proxy_type = backend.get_proxy_type
local ctx_address_type = backend.get_address_type
local ctx_address_host = backend.get_address_host
local ctx_address_bytes = backend.get_address_bytes
local ctx_address_port = backend.get_address_port
local ctx_write = backend.write
local ctx_free = backend.free
local htons = network.htons

local digest = crypto.digest
local sha224 = digest.new('SHA224')
sha224:update(settings.password)
local hash224 = sha224:final()
local flags = {}

function wa_lua_on_flags_cb(settings)
    return 0x01
end

function wa_lua_on_handshake_cb(ctx)
    local port = ctx_address_port(ctx)
    local atype = ctx_address_type(ctx)
    local res = hash224 .. char(0x0d, 0x0a, 0x01, atype)

    if atype == ADDRESS.DOMAIN then
        local host = ctx_address_host(ctx)
        res = res .. char(#host) .. host
    else
        local addr = ctx_address_bytes(ctx)
        res = res .. addr
    end

    res = res .. htons(port) .. char(0x0d, 0x0a)
    ctx_write(ctx, res)

    return true
end

function wa_lua_on_close_cb(ctx)
    ctx_free(ctx)
    return SUCCESS
end

