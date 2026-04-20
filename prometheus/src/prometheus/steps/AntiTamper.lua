local Step   = require("prometheus.step")
local Parser = require("prometheus.parser")
local Enums  = require("prometheus.enums")

local AntiTamper = Step:extend()
AntiTamper.Name = "Anti Tamper"
AntiTamper.SettingsDescriptor = {}

function AntiTamper:init(settings)
	self.Settings = settings or {}
end

local function parseFragment(code)
	local ok, parsed = pcall(function()
		return Parser:new({
			LuaVersion = Enums.LuaVersion.Lua51
		}):parse(code)
	end)

	if not ok or not parsed or not parsed.body or not parsed.body.statements then
		return nil
	end

	return parsed
end

function AntiTamper:apply(ast, pipeline)
	local frag1 = [==[
do
    local _E = (getfenv and getfenv(0)) or _G or {}
    local _type = _E.type or type
    local _pcall = _E.pcall or pcall
    local _error = _E.error or error
    local _rawget = _E.rawget or rawget
    local _rawset = _E.rawset or rawset
    local _rawequal = _E.rawequal or rawequal
    local _string = _E.string or string

    local function _fail()
        if _pcall then
            _pcall(function()
                if _rawset then
                    _rawset(_G, "pr".."int", function() end)
                    _rawset(_G, "wa".."rn", function() end)
                end
            end)
        end
        if _error then
            _error("", 0)
        end
    end

    if _type(_rawget) ~= "function" then _fail() end
    if _type(_rawset) ~= "function" then _fail() end
    if _type(_rawequal) ~= "function" then _fail() end

    if not _rawequal(_rawequal, rawequal) then
        _fail()
    end

    local _sentinel = (_string.byte and _string.byte("X", 1)) or 88
    local _t = {}

    _rawset(_t, 3, _sentinel)
    if _rawget(_t, 3) ~= _sentinel then
        _fail()
    end

    local _newproxy = _E.newproxy
    if _type(_newproxy) == "function" then
        local _ok = _pcall(function()
            local _sent = math.random(100, 999)
            local _px = _newproxy(true)
            local _mt = getmetatable(_px)
            if not _mt then
                _fail()
            end
            _mt.__len = function()
                return _sent
            end
            if #_px ~= _sent then
                _fail()
            end
        end)

        if not _ok then
            _fail()
        end
    end

    local _dump = _string.dump
    if _type(_dump) == "function" then
        local _okdump, _errdump = _pcall(function()
            return _dump(_string.char)
        end)

        if _okdump then
            _fail()
        end

        if _type(_errdump) == "string" then
            if not (_errdump:find("dump") or _errdump:find("unable") or _errdump:find("C")) then
                _fail()
            end
        end
    end
end
]==]

	local frag2 = [==[
do
    local _E = (getfenv and getfenv(0)) or _G or {}
    local _type = _E.type or type
    local _pcall = _E.pcall or pcall
    local _error = _E.error or error
    local _rawget = _E.rawget or rawget
    local _rawset = _E.rawset or rawset
    local _getmetatable = _E.getmetatable or getmetatable
    local _setmetatable = _E.setmetatable or setmetatable

    local function _fail()
        if _pcall then
            _pcall(function()
                if _rawset then
                    _rawset(_G, "pr".."int", function() end)
                    _rawset(_G, "wa".."rn", function() end)
                end
            end)
        end
        if _error then
            _error("", 0)
        end
    end

    local _n = 0
    if _setmetatable and _rawset then
        local _proxy = _setmetatable({}, {
            __newindex = function(t, k, v)
                _n = _n + 1
                _rawset(t, k, v)
            end
        })

        _proxy.a = 1
        _proxy.b = 2
        _proxy.c = 3

        if _n ~= 3 then
            _fail()
        end
    end

    local _mt = _getmetatable and _getmetatable("")
    if _mt and _mt.__newindex ~= nil then
        _fail()
    end

    if _pcall and _error then
        local _ok, _msg = _pcall(function()
            _error("_z_", 0)
        end)

        if _ok ~= false or type(_msg) ~= "string" then
            _fail()
        end
    end

    local _gfe = _E.getfenv
    if type(_gfe) == "function" then
        local _ok2, _env2 = _pcall(function()
            return _gfe(2)
        end)

        if _ok2 and type(_env2) == "table" then
            if not (type(_env2.rawget) == "function" and _env2.rawget == rawget) then
                _fail()
            end
        end
    end

    local _select = _E.select
    if type(_select) == "function" then
        if _select("#", 1, 2, 3, 4) ~= 4 then
            _fail()
        end
    end
end
]==]

	local frag3 = [==[
do
    local _E = (getfenv and getfenv(0)) or _G or {}
    local _type = _E.type or type
    local _pcall = _E.pcall or pcall
    local _error = _E.error or error
    local _rawset = _E.rawset or rawset
    local _string = _E.string or string
    local _debug = _E.debug
    local _os = _E.os

    local function _fail()
        if _pcall then
            _pcall(function()
                if _rawset then
                    _rawset(_G, "pr".."int", function() end)
                    _rawset(_G, "wa".."rn", function() end)
                end
            end)
        end
        if _error then
            _error("", 0)
        end
    end

    local _gfe = _E.getfenv
    if type(_gfe) == "function" then
        local _ok, _env = _pcall(function()
            return _gfe()
        end)

        if not _ok or type(_env) ~= "table" or type(_env.rawget) ~= "function" then
            _fail()
        end
    end

    if type(_debug) == "table" then
        local _getinfo = _debug.getinfo
        if type(_getinfo) == "function" then
            local _char = _string.char
            if type(_char) == "function" then
                local _okgi, _inf = _pcall(_getinfo, _char, "S")
                if not _okgi or not _inf or _inf.what ~= "C" then
                    _fail()
                end
            end
        end

        local _traceback = _debug.traceback
        if type(_traceback) == "function" then
            local _okt, _tstr = _pcall(_traceback)
            if _okt and type(_tstr) == "string" then
                if not _tstr:find("stack traceback") and not _tstr:find("Stack") then
                    _fail()
                end
            end
        end

        local _gethook = _debug.gethook
        local _sethook = _debug.sethook
        if type(_gethook) == "function" and type(_sethook) == "function" then
            local _hook = _gethook()
            if _hook ~= nil then
                _fail()
            end

            local _okh, _fn, _mask = _pcall(_gethook)
            if _okh and type(_mask) == "string" and #_mask > 0 then
                _fail()
            end
        end
    end

    if type(_os) == "table" and type(_os.clock) == "function" then
        local _t0 = _os.clock()
        local _sum = 0
        local _byte = _string.byte

        for _i = 1, 300 do
            if _byte then
                _sum = _sum + _byte("A", 1)
            else
                _sum = _sum + 65
            end
        end

        local _t1 = _os.clock()
        if (_t1 - _t0) > 0.05 then
            _fail()
        end
    end

    local _tostring = _E.tostring or tostring
    local _rawget = _E.rawget or rawget
    if type(_tostring) == "function" and type(_rawget) == "function" then
        local _traw = _tostring(_rawget)
        if type(_traw) ~= "string" or _traw:sub(1, 8) ~= "function" then
            _fail()
        end
    end
end
]==]

	local frag5 = [==[
do
    local _pcall = rawget(_G, "pc".."all") or pcall
    local _type = rawget(_G, "ty".."pe") or type
    local _error = rawget(_G, "er".."ror") or error
    local _rawset = rawget(_G, "raw".."set") or rawset

    local function _fail()
        _pcall(function()
            if _rawset then
                _rawset(_G, "pr".."int", function() end)
                _rawset(_G, "wa".."rn", function() end)
            end
        end)
        _error("", 0)
    end

    local _ok, _err = _pcall(function()
        local _hs = game and game.GetService and game:GetService("Http".."Service")
        if not _hs then return end

        local _src = {
            ["__k".."ey"] = 0xAB + 0xCD,
            ["__v".."al"] = 0xEF
        }

        local _json = _hs:JSONEncode(_src)
        local _dec = _hs:JSONDecode(_json)

        if not _dec
            or _dec["__k".."ey"] ~= (0xAB + 0xCD)
            or _dec["__v".."al"] ~= 0xEF
        then
            _fail()
        end
    end)

    if not _ok and _type(_err) == "string" and #_err > 2 then
        _fail()
    end
end
]==]

	local frag6 = [==[
do
    local _pcall = rawget(_G, "pc".."all") or pcall
    local _type = rawget(_G, "ty".."pe") or type
    local _error = rawget(_G, "er".."ror") or error
    local _rawset = rawget(_G, "raw".."set") or rawset

    local function _fail()
        _pcall(function()
            if _rawset then
                _rawset(_G, "pr".."int", function() end)
                _rawset(_G, "wa".."rn", function() end)
            end
        end)
        _error("", 0)
    end

    local _ok, _err = _pcall(function()
        local _inst = Instance and Instance.new and Instance.new("Folder")
        if _inst then
            local _gm = rawget(_G, "get".."meta".."table") or getmetatable
            local _mt = _gm and _gm(_inst) or nil

            if type(_mt) == "table" then
                _fail()
            end

            pcall(function()
                _inst:Destroy()
            end)
        end

        local _tf = rawget(_G, "type".."of") or typeof
        if _tf then
            if type("test") ~= _tf("test") then
                _fail()
            end

            if _tf(rawget) ~= "function" then
                _fail()
            end
        end
    end)

    if not _ok and _type(_err) == "string" and #_err > 2 then
        _fail()
    end
end
]==]

	local function inject(code, pos)
		local parsed = parseFragment(code)
		if not parsed then
			return 0
		end

		local inserted = 0
		local target = math.max(1, math.min(pos, #ast.body.statements + 1))

		for _, stmt in ipairs(parsed.body.statements) do
			pcall(function()
				if stmt.body and stmt.body.scope then
					stmt.body.scope:setParent(ast.body.scope)
				end
			end)

			table.insert(ast.body.statements, target + inserted, stmt)
			inserted = inserted + 1
		end

		return inserted
	end

	inject(frag1, 1)
	inject(frag2, math.floor(#ast.body.statements / 3) + 1)
	inject(frag3, math.floor(#ast.body.statements / 2) + 1)
	inject(frag5, math.floor(#ast.body.statements * 0.75) + 1)
	inject(frag6, #ast.body.statements + 1)

	return ast
end

return AntiTamper
