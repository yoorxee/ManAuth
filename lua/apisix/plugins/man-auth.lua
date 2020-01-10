local core     = require("apisix.core")
local hmac     = require("apisix.core.hmac")
local table	   = table
local string   = string
local tostring = tostring
local ngx      = ngx
local plugin_name = "man-auth"

local schema = {
    type = "object",
    additionalProperties = false
}
local _M = {
    version = 0.1,
    priority = 2510,
    type = 'auth',
    name = plugin_name,
    schema = schema,
}
function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end
    return true
end
local function get_authorization()
    local headers = ngx.req.get_headers()
    if headers.Authorization then
        return headers.Authorization
    end
    return nil
end
local function splitStr(input, delimiter)
    input = tostring(input)
    delimiter = tostring(delimiter)
    if (delimiter=='') then return false end
    local pos,arr = 0, {}
    for st,sp in function() return string.find(input, delimiter, pos, true) end do
        table.insert(arr, string.sub(input, pos, st - 1))
        pos = sp + 1
    end
    table.insert(arr, string.sub(input, pos))
    return arr
end
local function urlEncode(s)
     s = string.gsub(s, "([^%w%.%- ])", function(c) return string.format("%%%02X", string.byte(c)) end)
    return string.gsub(s, " ", "+")
end
local function exception(code, message,reqId)
	core.response.set_header("Content-Type", "application/json")
	ngx.status = code
    ngx.say(core.json.encode({code = code, message = message, requestId = reqId, data = {}}))
	core.log.error(code, message, reqId)
    return ngx.exit(code)
end
function _M.rewrite(conf, ctx)
	ngx.req.set_header("Man-requestid", ctx.var.request_id)
    local jwt_token = get_authorization()
    if not jwt_token then
		exception(401, "参数错误，签名参数Authorization异常",ctx.var.request_id)
    end
	-- check params
	local ak = nil
	local timestamp = nil
	local region = nil
	local headers = nil
	local signature = nil
	local expire_time = 5 * 60
	local req_method = ngx.var.request_method
	
    local authorization = splitStr(jwt_token,"/")
	if table.getn(authorization) ~= 5 then 
		exception(401, "参数错误，缺少签名所需参数",ctx.var.request_id)
	end
	ak 			= authorization[1]
	timestamp 	= authorization[2]
	region 		= authorization[3]
	headers 	= authorization[4]
	signature 	= authorization[5]
	local key = nil
    if ak then
		key = "apis/" ..  ak
	else
		exception(500, "参数错误，签名参数access key异常",ctx.var.request_id)
    end
    --local res, err = core.etcd.get(key)
    local res, err = core.etcd.globalget(key)
	if not res then
		exception(500, "服务器错误，获取签名服务失败",ctx.var.request_id)
    end
	if res.status ~= 200 then
        exception(500, "服务器错误，access key不正确",ctx.var.request_id)
    end
	local sk, err = res.body.node.value.secret
	if err then
		exception(500, "服务器错误，无法获取sk",ctx.var.request_id)
	end
	if timestamp == nil or timestamp == "" or string.len(timestamp) ~= 10 then
		exception(401, "参数错误，签名参数timestamp异常",ctx.var.request_id)
	end
	timestamp = tonumber(timestamp)
	if not timestamp then
		exception(401, "参数错误，timestamp格式错误",ctx.var.request_id)
	end
	if ngx.now() - timestamp < -expire_time or ngx.now() - timestamp >= expire_time then
		local _now = ngx.now()
		core.response.set_header("server_time", _now)
		exception(401, "参数错误，timestamp时间过期",ctx.var.request_id)
	end
	-- check signature
	local uri = urlEncode(ngx.var.request_uri)
	if not uri then
		uri = "/"
	end
	local header_key_val = {}
	if headers == nil or headers == "" then
		headers = "Host;"
	end
	local header_key = splitStr(headers,";")
	for _, v in pairs(header_key) do
		if v ~= "" and v ~= nil then
			local _v = core.request.header(ctx, v)
			if _v ~= "" and v ~= nil then
				table.insert(header_key_val, string.lower(urlEncode(v)) .. ":" .. urlEncode(_v) )
			end
		end
	end
	table.sort(header_key_val)
	local CanonicalRequest = req_method .. "/" .. uri .. "/" .. table.concat(header_key_val, "/");
	local authStringPrefix = ak .. "/" .. timestamp .. "/" .. region
	local SigningKey_sha1 = hmac:new(sk, hmac.ALGOS.SHA256)
	local SigningKey = SigningKey_sha1:final(authStringPrefix, true)
	local nSignature_sha1 = hmac:new(SigningKey, hmac.ALGOS.SHA256)
	local nSignature = nSignature_sha1:final(CanonicalRequest, true)
	if nSignature ~= signature then
		core.log.error("SigningKey:",SigningKey)
		core.log.error("authStringPrefix:",authStringPrefix)
		core.log.error("nSignature:",nSignature)
		core.log.error("CanonicalRequest:",CanonicalRequest)
		exception(401, "参数错误，签名认证失败",ctx.var.request_id)
	end
end

return _M