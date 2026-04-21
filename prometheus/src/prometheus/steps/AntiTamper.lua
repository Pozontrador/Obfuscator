local Step   = require("prometheus.step");
local Parser = require("prometheus.parser");
local Enums  = require("prometheus.enums");

local AntiTamper = Step:extend();
AntiTamper.Name = "Anti Tamper";
AntiTamper.SettingsDescriptor = {};
function AntiTamper:init(settings) end

function AntiTamper:apply(ast, pipeline)

    -- Frag1: tipo, rawequal, sentinel, newproxy, string.dump
    local frag1 = [==[
    do
        local _rg1  = rawget
        local _gf1  = _rg1 and _rg1(_G, "get".."fe".."nv") or nil
        local _E    = (_gf1 and _gf1()) or _G or {}
        local _rs   = _E["raw".."set"]
        local _rg   = _E["raw".."get"]
        local _req  = _E["raw".."equal"]
        local _ty   = _E["ty".."pe"]
        local _pc   = _E["pc".."all"]
        local _sb   = (_E["st".."ring"] or {})["by".."te"]
        local _sc   = (_E["st".."ring"] or {})["ch".."ar"]
        local _sdp  = (_E["st".."ring"] or {})["du".."mp"]
        local _er   = _E["er".."ror"]
        local _nop  = function() end

        -- [A] type checks on critical functions
        if not (_ty and _ty(_rs)=="function") then
            _pc and _pc(function() _rs and _rs(_E,"pr".."int",_nop) end)
            if _ty and _ty(_er)=="function" then _er("",0) end
        end
        if not (_ty and _ty(_rg)=="function") then
            _pc and _pc(function() _rs and _rs(_E,"wa".."rn",_nop) end)
            if _ty and _ty(_er)=="function" then _er("",0) end
        end
        if not (_ty and _ty(_req)=="function") then
            if _ty and _ty(_er)=="function" then _er("",0) end
        end

        -- [B] rawequal identity: rawequal must equal itself
        if not (_req and _req(_req, rawequal)) then
            if _ty and _ty(_er)=="function" then _er("",0) end
        end

        -- [C] rawget/rawset sentinel round-trip
        local _sd = (_sb and _sb("X",1)) or 88
        local _t1 = {}
        if _rs and _rg then
            _rs(_t1, 99, _sd)
            if _rg(_t1, 99) ~= _sd then
                _pc and _pc(function() _rs(_E,"pr".."int",_nop) end)
                if _ty and _ty(_er)=="function" then _er("",0) end
            end
        end

        -- [D] newproxy __len check
        local _np = _E["new".."proxy"]
        if _ty and _ty(_np)=="function" then
            local _sentinel = math.random(1000,9999)
            local _px = _np(true)
            local _ok_np = _pc and _pc(function()
                _E["get".."meta".."table"](_px).__len = function() return _sentinel end
            end)
            if _ok_np then
                local _oklen, _len = _pc(function() return #_px end)
                if not _oklen or _len ~= _sentinel then
                    if _ty and _ty(_er)=="function" then _er("",0) end
                end
            end
        end

        -- [E] string.dump must fail on native functions
        if _ty and _ty(_sdp)=="function" then
            local _okdump, _dmperr = _pc(function() _sdp(_sc) end)
            if _okdump then
                if _ty and _ty(_er)=="function" then _er("",0) end
            end
            if not _okdump and _ty(_dmperr)=="string" then
                if not (_dmperr:find("dump") or _dmperr:find("unable") or _dmperr:find("C")) then
                    if _ty and _ty(_er)=="function" then _er("",0) end
                end
            end
        end

        -- [F] Metamethod protection: __index on table must not be hooked
        -- A clean env has no __index on the global table
        local _gmt = _E["get".."meta".."table"]
        if _ty and _ty(_gmt)=="function" then
            local _mt_g = _gmt(_E)
            -- If _G has a metatable with __index pointing to a function, env is proxied
            if _mt_g and _ty(_mt_g.__index)=="function" then
                if _ty and _ty(_er)=="function" then _er("",0) end
            end
        end
    end
    ]==]

    -- Frag2: newindex counter, getmetatable, pcall path, getfenv(2), select
    local frag2 = [==[
    do
        local _rg2  = rawget
        local _gf2  = _rg2 and _rg2(_G, "get".."fe".."nv") or nil
        local _E2   = (_gf2 and _gf2()) or _G or {}
        local _rs2  = _E2["raw".."set"]
        local _rg2b = _E2["raw".."get"]
        local _smt2 = _E2["set".."meta".."table"]
        local _gmt2 = _E2["get".."meta".."table"]
        local _pc2  = _E2["pc".."all"]
        local _ty2  = _E2["ty".."pe"]
        local _er2  = _E2["er".."ror"]
        local _nop2 = function() end

        -- [G] __newindex counter integrity
        local _n2 = 0
        if _smt2 and _rs2 then
            local _px2 = _smt2({},{__newindex=function(t,k,v) _n2=_n2+1; _rs2(t,k,v) end})
            _px2.a=1; _px2.b=2; _px2.c=3
            if _n2 ~= 3 then
                _pc2 and _pc2(function() _rs2 and _rs2(_E2,"pr".."int",_nop2) end)
                if _ty2 and _ty2(_er2)=="function" then _er2("",0) end
            end
        end

        -- [H] string metatable __newindex must be nil
        if _gmt2 then
            local _mt2 = _gmt2("")
            if _mt2 and _mt2.__newindex ~= nil then
                if _ty2 and _ty2(_er2)=="function" then _er2("",0) end
            end
        end

        -- [I] pcall error path integrity
        if _pc2 and _er2 then
            local _a, _b = _pc2(function() _er2("_z_",0) end)
            if _a ~= false or not (_ty2 and _ty2(_b)=="string") then
                _pc2(function() _rs2 and _rs2(_E2,"wa".."rn",_nop2) end)
                if _ty2 and _ty2(_er2)=="function" then _er2("",0) end
            end
        end

        -- [J] getfenv(2) caller env integrity
        local _gfe2 = _E2["get".."fe".."nv"]
        if _ty2 and _ty2(_gfe2)=="function" then
            local _ok2, _env2 = _pc2(function() return _gfe2(2) end)
            if _ok2 and _ty2(_env2)=="table" then
                if not (_rg2b and _rg2b(_env2, "raw".."get") ~= nil or
                        _env2["raw".."get"] ~= nil) then
                    if _ty2 and _ty2(_er2)=="function" then _er2("",0) end
                end
            end
        end

        -- [K] select("#") count integrity
        local _sel2 = _E2["se".."lect"]
        if _ty2 and _ty2(_sel2)=="function" then
            if _sel2("#",1,2,3,4) ~= 4 then
                if _ty2 and _ty2(_er2)=="function" then _er2("",0) end
            end
        end

        -- [L] Stack depth check: pcall nesting level must be consistent
        local _depth2 = 0
        _pc2(function()
            _pc2(function()
                _depth2 = _depth2 + 1
            end)
            _depth2 = _depth2 + 1
        end)
        if _depth2 ~= 2 then
            if _ty2 and _ty2(_er2)=="function" then _er2("",0) end
        end
    end
    ]==]

    -- Frag3: getfenv, debug checks, os.clock, tostring, anti-debug hooks
    local frag3 = [==[
    do
        local _rg3  = rawget
        local _gf3  = _rg3 and _rg3(_G, "get".."fe".."nv") or nil
        local _E3   = (_gf3 and _gf3()) or _G or {}
        local _ty3  = _E3["ty".."pe"]
        local _er3  = _E3["er".."ror"]
        local _rs3  = _E3["raw".."set"]
        local _pc3  = _E3["pc".."all"]
        local _nop3 = function() end

        -- [M] getfenv env integrity
        local _gfe3 = _E3["get".."fe".."nv"]
        if _ty3 and _ty3(_gfe3)=="function" then
            local _ok3, _env3 = _pc3(_gfe3)
            if not _ok3 or not (_ty3(_env3)=="table" and _ty3(_env3["raw".."get"])=="function") then
                _pc3(function() if _rs3 then _rs3(_E3,"pr".."int",_nop3) end end)
                if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
            end
        end

        -- [N] debug.getinfo: string.char must be C function
        local _dbg3 = _E3["deb".."ug"]
        if _ty3 and _ty3(_dbg3)=="table" then
            local _gi3 = _dbg3["get".."info"]
            if _ty3(_gi3)=="function" then
                local _str3 = _E3["st".."ring"]
                local _sc3  = _str3 and _str3["ch".."ar"]
                if _sc3 then
                    local _okgi, _inf3 = _pc3(_gi3, _sc3, "S")
                    if not _okgi or (_inf3 and _inf3.what ~= "C") then
                        if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
                    end
                end
            end

            -- [O] traceback format check
            local _tb3 = _dbg3["trace".."back"]
            if _ty3(_tb3)=="function" then
                local _okt, _tstr = _pc3(_tb3)
                if _okt and _ty3(_tstr)=="string" then
                    if not _tstr:find("stack traceback") and not _tstr:find("Stack") then
                        if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
                    end
                end
            end

            -- [P] Anti-debug: sethook/gethook — single check, no duplicate
            local _gh3 = _dbg3["get".."hook"]
            local _sh3 = _dbg3["set".."hook"]
            if _ty3(_gh3)=="function" and _ty3(_sh3)=="function" then
                -- If any hook is currently active, a debugger is attached
                local _hookP = _gh3()
                if _hookP ~= nil then
                    if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
                end
                -- Also check mask: count/line hooks = profiler/tracer
                local _okP, _fnP, _maskP = _pc3(_gh3)
                if _okP and _ty3(_maskP)=="string" and #_maskP > 0 then
                    if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
                end
            end

            -- [Q] debug.getlocal: verify level 1 is accessible but not overridden
            local _gl3 = _dbg3["get".."local"]
            if _ty3(_gl3)=="function" then
                local _okgl, _lname = _pc3(function() return _gl3(1,1) end)
                -- A hooked debug.getlocal may return nil or crash
                -- Native: returns a valid local name string or nil if no locals
                -- If it returns something unexpected, flag it
                if not _okgl and _ty3(_lname)=="string" and #_lname > 50 then
                    if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
                end
            end
        end

        -- [R] os.clock timing — wrapped calls shouldn't be 50x slower
        local _os3 = _E3["os"]
        if _ty3 and _ty3(_os3)=="table" and _ty3(_os3["cl".."ock"])=="function" then
            local _clk = _os3["cl".."ock"]
            local _t0  = _clk()
            local _sum = 0
            for _i = 1, 200 do
                _sum = _sum + ((_E3["st".."ring"] or {})["by".."te"] and
                    _E3["st".."ring"].byte("A",1) or 65)
            end
            local _t1 = _clk()
            if (_t1 - _t0) > 0.05 then
                if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
            end
        end

        -- [S] tostring of native must start with "function"
        local _ts3  = _E3["to".."string"]
        local _raw3 = _E3["raw".."get"]
        if _ty3 and _ty3(_ts3)=="function" and _ty3(_raw3)=="function" then
            local _traw = _ts3(_raw3)
            if _ty3(_traw)~="string" or _traw:sub(1,8)~="function" then
                if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
            end
        end
    end
    ]==]

    -- Frag4: RunService + PlaceId + DataModel checks
    local frag4 = [==[
    do
        local _rg4  = rawget
        local _ty4  = _rg4 and _rg4(_G, "ty".."pe")  or type
        local _pc4  = _rg4 and _rg4(_G, "pc".."all") or pcall
        local _er4  = _rg4 and _rg4(_G, "er".."ror") or error
        local _nop4 = function() end

        -- [T] RunService IsClient XOR IsServer
        local _ok4a, _rs4 = _pc4(function()
            return game:GetService("Run".."Service")
        end)
        if _ok4a and _rs4 then
            local _ok4b, _ic4 = _pc4(function() return _rs4:IsClient() end)
            local _ok4c, _is4 = _pc4(function() return _rs4:IsServer() end)
            if _ok4b and _ok4c then
                if _ic4 == _is4 then
                    _pc4(function() rawset(_G,"pr".."int",_nop4) end)
                    if _ty4(_er4)=="function" then _er4("",0) end
                end
            end
        end

        -- [U] game.PlaceId must be positive integer
        local _ok4d, _pid4 = _pc4(function() return game.PlaceId end)
        if _ok4d then
            if _ty4(_pid4)~="number" or _pid4~=math.floor(_pid4) or _pid4 < 0 then
                _pc4(function() rawset(_G,"wa".."rn",_nop4) end)
                if _ty4(_er4)=="function" then _er4("",0) end
            end
        end

        -- [V] tostring(game) must contain DataModel
        local _ok4e, _gstr4 = _pc4(function() return tostring(game) end)
        if _ok4e and _ty4(_gstr4)=="string" then
            if not _gstr4:find("DataModel") and not _gstr4:find("Game") then
                if _ty4(_er4)=="function" then _er4("",0) end
            end
        end
    end
    ]==]

    -- Frag5: HttpService JSON round-trip integrity
    local frag5 = [==[
    do
        local _pc5  = rawget and rawget(_G, "pc".."all") or pcall
        local _ty5  = rawget and rawget(_G, "ty".."pe")  or type
        local _er5  = rawget and rawget(_G, "er".."ror") or error
        local _nop5 = function() end
        local _ok5, _err5 = _pc5(function()
            local _hs = game and game.GetService and game:GetService("Http".."Service")
            if not _hs then return end
            -- Deterministic key/value pair
            local _key5  = math.floor(0xAB + 0xCD)
            local _val5  = math.floor(0xEF)
            local _tbl5  = {}
            rawset(_tbl5, "__k5", _key5)
            rawset(_tbl5, "__v5", _val5)
            local _json5 = _hs:JSONEncode(_tbl5)
            local _dec5  = _hs:JSONDecode(_json5)
            if not _dec5 or _dec5["__k5"] ~= _key5 or _dec5["__v5"] ~= _val5 then
                _pc5(function() rawset(_G,"pr".."int",_nop5) end)
                if _ty5(_er5)=="function" then _er5("",0) end
            end
        end)
        if not _ok5 and _ty5(_err5)=="string" and #_err5 > 2 then
            _pc5(function() rawset(_G,"pr".."int",_nop5) rawset(_G,"wa".."rn",_nop5) end)
            if _ty5(_er5)=="function" then _er5("",0) end
        end
    end
    ]==]

    -- Frag6: Instance.new identity + typeof consistency
    local frag6 = [==[
    do
        local _pc6  = rawget and rawget(_G, "pc".."all") or pcall
        local _ty6  = rawget and rawget(_G, "ty".."pe")  or type
        local _er6  = rawget and rawget(_G, "er".."ror") or error
        local _nop6 = function() end
        local _ok6, _err6 = _pc6(function()
            -- [W] Instance.new metatable must NOT be a plain Lua table
            local _inst6 = Instance and Instance.new and Instance.new("Folder")
            if _inst6 then
                local _gm6 = rawget(_G, "get".."meta".."table") or getmetatable
                local _mt6 = _gm6 and _gm6(_inst6)
                -- Native Roblox object: metatable not accessible as plain table
                if _ty6(_mt6)=="table" then
                    _pc6(function() rawset(_G,"pr".."int",_nop6) end)
                    if _ty6(_er6)=="function" then _er6("",0) end
                end
                _pc6(function() _inst6:Destroy() end)
            end

            -- [X] typeof vs type consistency
            local _tf6 = rawget(_G, "type".."of") or typeof
            if _tf6 then
                if _ty6("t") ~= _tf6("t") then
                    if _ty6(_er6)=="function" then _er6("",0) end
                end
                if _tf6(rawget) ~= "function" then
                    if _ty6(_er6)=="function" then _er6("",0) end
                end
            end
        end)
        if not _ok6 and _ty6(_err6)=="string" and #_err6 > 2 then
            _pc6(function() rawset(_G,"pr".."int",_nop6) rawset(_G,"wa".."rn",_nop6) end)
            if _ty6(_er6)=="function" then _er6("",0) end
        end
    end
    ]==]

    local function inject(code, pos)
        local ok, parsed = pcall(function()
            return Parser:new({LuaVersion = Enums.LuaVersion.Lua51}):parse(code)
        end)
        if not ok or not parsed then return 0 end
        local n = 0
        for _, stmt in ipairs(parsed.body.statements) do
            pcall(function()
                if stmt.body then stmt.body.scope:setParent(ast.body.scope) end
            end)
            table.insert(ast.body.statements, pos + n, stmt)
            n = n + 1
        end
        return n
    end

    inject(frag1, 1)
    inject(frag2, math.floor(#ast.body.statements / 3) + 1)
    inject(frag3, math.floor(#ast.body.statements / 2) + 1)
    inject(frag4, math.floor(#ast.body.statements * 0.65) + 1)
    inject(frag5, math.floor(#ast.body.statements * 0.80) + 1)
    inject(frag6, math.max(1, #ast.body.statements))

    return ast
end

return AntiTamper;
