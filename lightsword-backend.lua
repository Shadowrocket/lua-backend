-- file: lua/lightsword-backend.lua

local http = require 'http'
local crypto = require 'crypto'
local network = require 'network'
local backend = require 'backend'

local char = string.char
local byte = string.byte
local find = string.find
local sub = string.sub
local rep = string.rep
local format = string.format
local random = math.random
local floor = math.floor

local ADDRESS = backend.ADDRESS
local PROXY = backend.PROXY
local SUPPORT = backend.SUPPORT
local ERROR = backend.RESULT.ERROR
local SUCCESS = backend.RESULT.SUCCESS
local IGNORE = backend.RESULT.IGNORE
local HANDSHAKE = backend.RESULT.HANDSHAKE

local ctx_uuid = backend.get_uuid
local ctx_proxy_type = backend.get_proxy_type
local ctx_address_type = backend.get_address_type
local ctx_address_host = backend.get_address_host
local ctx_address_bytes = backend.get_address_bytes
local ctx_address_port = backend.get_address_port
local ctx_write = backend.write
local ctx_free = backend.free
local debug = backend.debug
local htons = network.htons

local supported_ciphers = {
    ['aes-128-cfb'] = {key=16, iv=16},
    ['aes-128-ofb'] = {key=16, iv=16},
    ['aes-192-cfb'] = {key=24, iv=16},
    ['aes-192-ofb'] = {key=24, iv=16},
    ['aes-256-cfb'] = {key=32, iv=16},
    ['aes-256-ofb'] = {key=32, iv=16},
    ['bf-cfb'] = {key=16, iv=8},
    ['camellia-128-cfb'] = {key=16, iv=16},
    ['camellia-192-cfb'] = {key=24, iv=16},
    ['camellia-256-cfb'] = {key=32, iv=16},
    ['cast5-cfb'] = {key=16, iv=8},
    ['des-cfb'] = {key=8, iv=8},
    ['idea-cfb'] = {key=16, iv=8},
    ['rc2-cfb'] = {key=16, iv=8},
    ['rc4'] = {key=16, iv=0},
    ['rc4-md5'] = {key=16, iv=16},
    ['seed-cfb'] = {key=16, iv=16},
}


local cache = {}
local rand = crypto.rand
local encrypt = crypto.encrypt
local decrypt = crypto.decrypt

local algorithm = settings.method
local password = settings.password
local key_len = supported_ciphers[algorithm].key
local iv_len = supported_ciphers[algorithm].iv
local key

if #password > key_len then
    key = sub(password, 1, key_len)
elseif #password < key_len then
    local len = floor(key_len / #password) + 1
    key = sub(rep(password, len), 1, key_len)
else
    key = password
end

local function wa_lua_handshake(ctx)
    local uuid = ctx_uuid(ctx)
    local item = cache[uuid]
    local iv = rand.bytes(iv_len)
    local atyp = ctx_address_type(ctx)
    local port = htons(ctx_address_port(ctx))
    local len = random(255)
    local padding = rand.bytes(len)
    local address

    if atyp == ADDRESS.DOMAIN then
        local host = ctx_address_host(ctx)
        address = char(#host) .. host .. port
    else
        local addr = ctx_address_bytes(ctx)
        address = addr .. port
    end

    local cryptor = encrypt.new(algorithm, key, iv)
    local data = char(5) .. char(len) .. padding .. char(5, 1, 0, atyp) .. address
    local payload = cryptor:update(data) .. cryptor:final()

    cryptor = encrypt.new(algorithm, key, iv)

    item['head'] = #address + 4
    item['cryptor'] = cryptor

    return iv .. payload
end

function wa_lua_on_flags_cb(ctx)
    local uuid = ctx_uuid(ctx)
    cache[uuid] = {}
    return 0
end

function wa_lua_on_handshake_cb(ctx)
    local uuid = ctx_uuid(ctx)
    local item = cache[uuid]

    if item['stage'] == 'handshake' then
        return true
    end

    if not item['stage'] then
        item['stage'] = 'connect'
        local res = wa_lua_handshake(ctx)
        ctx_write(ctx, res)
    end

    return false
end

function wa_lua_on_read_cb(ctx, buf)
    local uuid = ctx_uuid(ctx)
    local item = cache[uuid]

    if not item['decryptor'] then
        local head = item['head']

        if not head then
            return ERROR, nil
        end

        if #buf < iv_len then
            return ERROR, nil
        end

        local iv = sub(buf, 1, iv_len)
        local decryptor = decrypt.new(algorithm, key, iv)
        local data = sub(buf, iv_len + 1)
        local text = decryptor:update(data)
        local padding = byte(text, 1)
        local len = iv_len + 1 + padding + head

        if len ~= #buf then
            return ERROR, nil
        end

        decryptor = decrypt.new(algorithm, key, iv)

        item['stage'] = 'handshake'
        item['decryptor'] = decryptor

        return HANDSHAKE, nil
    else
        local decryptor = item['decryptor']
        local res = decryptor:update(buf)
        return SUCCESS, res
    end

end

function wa_lua_on_write_cb(ctx, buf)
    local uuid = ctx_uuid(ctx)
    local item = cache[uuid]
    local cryptor = item['cryptor']
    local res = cryptor:update(buf)
    return SUCCESS, res
end

function wa_lua_on_close_cb(ctx)
    local uuid = ctx_uuid(ctx)
    if cache[uuid] then
        cache[uuid] = nil
    end
    ctx_free(ctx)
    return SUCCESS
end

