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
        local _rg1 = rawget
        local _gf1 = _rg1 and _rg1(_G, "get".."fe".."nv") or nil
        local _E = (_gf1 and _gf1()) or _G or {}
        local _fn = {
            _E["raw".."set"],  _E["raw".."get"],  _E["raw".."equal"],
            _E["ty".."pe"],    _E["pc".."all"],
            (_E["st".."ring"] or {})["by".."te"],
            (_E["st".."ring"] or {})["ch".."ar"],
            (_E["st".."ring"] or {})["du".."mp"],
        }
        local _er  = _E["er".."ror"]
        local _nop = function() end

        -- [A] type checks
        if not (_fn[4] and _fn[4](_fn[1]) == "function") then
            _fn[5] and _fn[5](function() _fn[1] and _fn[1](_E,"pr".."int",_nop) end)
            if _fn[4] and _fn[4](_er)=="function" then _er("",0) end
        end
        if not (_fn[4] and _fn[4](_fn[2]) == "function") then
            _fn[5] and _fn[5](function() _fn[1] and _fn[1](_E,"wa".."rn",_nop) end)
            if _fn[4] and _fn[4](_er)=="function" then _er("",0) end
        end
        if not (_fn[4] and _fn[4](_fn[3]) == "function") then
            if _fn[4] and _fn[4](_er)=="function" then _er("",0) end
        end

        -- [B] rawequal self-check
        if not (_fn[3] and _fn[3](_fn[3], rawequal)) then
            if _fn[4] and _fn[4](_er)=="function" then _er("",0) end
        end

        -- [C] rawget/rawset sentinel
        local _sd = (_fn[6] and _fn[6]("X",1)) or 88
        local _t1 = {}
        if _fn[1] and _fn[2] then
            _fn[1](_t1, 3, _sd)
            if _fn[2](_t1, 3) ~= _sd then
                _fn[5] and _fn[5](function() _fn[1] and _fn[1](_E,"pr".."int",_nop) end)
                if _fn[4] and _fn[4](_er)=="function" then _er("",0) end
            end
        end

        -- [D] newproxy check: se disponível, __len deve funcionar corretamente
        local _np = _E["new".."proxy"]
        if _fn[4] and _fn[4](_np) == "function" then
            local _sentinel = math.random(100,999)
            local _px2 = _np(true)
            local _ok_np = _fn[5] and _fn[5](function()
                _E["get".."meta".."table"](_px2).__len = function() return _sentinel end
            end)
            if _ok_np then
                local _oklen, _len = _fn[5](function() return #_px2 end)
                if not _oklen or _len ~= _sentinel then
                    if _fn[4] and _fn[4](_er)=="function" then _er("",0) end
                end
            end
        end

        -- [E] string.dump deve falhar em funções nativas (não é função Lua)
        if _fn[4] and _fn[4](_fn[8]) == "function" then
            local _okdump, _dmperr = _fn[5](function() _fn[8](_fn[7]) end)
            if _okdump then
                -- dump de string.char funcionou — é wrapper Lua, não nativo
                if _fn[4] and _fn[4](_er)=="function" then _er("",0) end
            end
            if not _okdump and _fn[4] and _fn[4](_dmperr) == "string" then
                -- deve conter "unable to dump given function" ou similar
                -- se a mensagem for diferente, pode ser wrapper
                if not (_dmperr:find("dump") or _dmperr:find("unable") or _dmperr:find("C")) then
                    if _fn[4] and _fn[4](_er)=="function" then _er("",0) end
                end
            end
        end
    end
    ]==]

    -- Frag2: newindex counter, getmetatable, pcall path, getfenv(2)
    local frag2 = [==[
    do
        local _rg2 = rawget
        local _gf2 = _rg2 and _rg2(_G, "get".."fe".."nv") or nil
        local _E2 = (_gf2 and _gf2()) or _G or {}
        local _fn2 = {
            _E2["raw".."set"],           _E2["raw".."get"],
            _E2["set".."meta".."table"], _E2["get".."meta".."table"],
            _E2["pc".."all"],            _E2["ty".."pe"],
            (_E2["st".."ring"] or {})["by".."te"],
        }
        local _er2 = _E2["er".."ror"]
        local _nop2 = function() end

        -- [F] __newindex counter
        local _n2 = 0
        if _fn2[3] and _fn2[1] then
            local _px = _fn2[3]({},{__newindex=function(t,k,v) _n2=_n2+1; _fn2[1](t,k,v) end})
            _px.a=1; _px.b=2; _px.c=3
            if _n2 ~= 3 then
                _fn2[5] and _fn2[5](function() _fn2[1] and _fn2[1](_E2,"pr".."int",_nop2) end)
                if _fn2[6] and _fn2[6](_er2)=="function" then _er2("",0) end
            end
        end

        -- [G] string metatable __newindex nil
        if _fn2[4] then
            local _mt2 = _fn2[4]("")
            if _mt2 and _mt2.__newindex ~= nil then
                if _fn2[6] and _fn2[6](_er2)=="function" then _er2("",0) end
            end
        end

        -- [H] pcall error path
        if _fn2[5] and _er2 then
            local _a,_b = _fn2[5](function() _er2("_z_",0) end)
            if _a ~= false or not (_fn2[6] and _fn2[6](_b)=="string") then
                _fn2[5](function() _fn2[1] and _fn2[1](_E2,"wa".."rn",_nop2) end)
                if _fn2[6] and _fn2[6](_er2)=="function" then _er2("",0) end
            end
        end

        -- [I] getfenv(2) caller env — executores às vezes esquecem nível 2
        local _gfe2 = _E2["get".."fe".."nv"]
        if _fn2[6] and _fn2[6](_gfe2)=="function" then
            local _ok2, _env2 = _fn2[5](function() return _gfe2(2) end)
            if _ok2 and _fn2[6](_env2)=="table" then
                if not (_fn2[2] and _fn2[2](_env2["raw".."get"],rawget)) then
                    if _fn2[6] and _fn2[6](_er2)=="function" then _er2("",0) end
                end
            end
        end

        -- [J] select count integrity
        local _sel2 = _E2["se".."lect"]
        if _fn2[6] and _fn2[6](_sel2)=="function" then
            if _sel2("#",1,2,3,4) ~= 4 then
                if _fn2[6] and _fn2[6](_er2)=="function" then _er2("",0) end
            end
        end
    end
    ]==]

-- Frag3: getfenv, debug.getinfo, os.clock timing, debug.traceback format
    local frag3 = [==[
    do
        local _rg3 = rawget
        local _gf3 = _rg3 and _rg3(_G, "get".."fe".."nv") or nil
        local _E3 = (_gf3 and _gf3()) or _G or {}
        local _ty3 = _E3["ty".."pe"]
        local _er3 = _E3["er".."ror"]
        local _rs3 = _E3["raw".."set"]
        local _pc3 = _E3["pc".."all"]
        local _nop3 = function() end

        -- [K] getfenv: se ausente = OK, se presente mas env corrompido = detona
        local _gfe3 = _E3["get".."fe".."nv"]
        if not (_ty3 and _ty3(_gfe3)=="function") then
            -- feature ausente: ok, nao detona
            local _dummy = 0
        else
            local _ok3, _env3 = _pc3(_gfe3)
            if not _ok3 or not (_ty3(_env3)=="table" and _ty3(_env3["raw".."get"])=="function") then
                _pc3(function() if _rs3 then _rs3(_E3,"pr".."int",_nop3) end end)
                if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
            end
        end

        -- [L] debug: se ausente = OK, se presente e hookeado = detona
        local _dbg3 = _E3["deb".."ug"]
        if not (_ty3 and _ty3(_dbg3)=="table") then
            local _dummy2 = 0
        else
            local _gi3 = _dbg3["get".."info"]
            if _ty3 and _ty3(_gi3)=="function" then
                local _str3 = _E3["st".."ring"]
                local _sc3  = _str3 and _str3["ch".."ar"] or nil
                if _sc3 then
                    local _okgi, _inf3 = _pc3(_gi3, _sc3, "S")
                    if not _okgi or (_inf3 and _inf3.what ~= "C") then
                        if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
                    end
                end
            end
            -- [M] traceback format
            local _tb3 = _dbg3["trace".."back"]
            if _ty3 and _ty3(_tb3)=="function" then
                local _okt, _tstr = _pc3(_tb3)
                if _okt and _ty3(_tstr)=="string" then
                    if not _tstr:find("stack traceback") and not _tstr:find("Stack") then
                        if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
                    end
                end
            end
        end

        -- [N] os.clock timing
        local _os3 = _E3["os"]
        if not (_ty3 and _ty3(_os3)=="table" and _ty3(_os3["cl".."ock"])=="function") then
            local _dummy3 = 0
        else
            local _clk = _os3["cl".."ock"]
            local _t0 = _clk()
            local _sum = 0
            for _i=1,500 do
                _sum = _sum + ((_E3["st".."ring"] or {})["by".."te"] and
                    (_E3["st".."ring"].byte("A",1)) or 65)
            end
            local _t1 = _clk()
            if (_t1 - _t0) > 0.05 then
                if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
            end
        end

        -- [O] tostring de nativo
        local _ts3 = _E3["to".."string"]
        local _raw3 = _E3["raw".."get"]
        if not (_ty3 and _ty3(_ts3)=="function" and _ty3(_raw3)=="function") then
            local _dummy4 = 0
        else
            local _traw = _ts3(_raw3)
            if _ty3(_traw)~="string" or _traw:sub(1,8)~="function" then
                if _ty3 and _ty3(_er3)=="function" then _er3("",0) end
            end
        end
        -- [P] Anti-debug: sethook/gethook detection
        local _dbgP = _E3["deb".."ug"]
        if _ty3 and _ty3(_dbgP)=="table" then
            local _ghP = _dbgP["get".."hook"]
            local _shP = _dbgP["set".."hook"]
            if _ty3(_ghP)=="function" and _ty3(_shP)=="function" then
                local _hookP = _ghP()
                if _hookP ~= nil then
                    if _ty3(_er3)=="function" then _er3("",0) end
                end
                local _okP, _fnP, _maskP = _pc3(_ghP)
                if _okP and _ty3(_maskP)=="string" and #_maskP > 0 then
                    if _ty3(_er3)=="function" then _er3("",0) end
                end
            end
        end
        -- [P] Anti-debug: sethook/gethook detection
        local _dbgP = _E3["deb".."ug"]
        if _ty3 and _ty3(_dbgP)=="table" then
            local _ghP = _dbgP["get".."hook"]
            local _shP = _dbgP["set".."hook"]
            if _ty3(_ghP)=="function" and _ty3(_shP)=="function" then
                local _hookP = _ghP()
                if _hookP ~= nil then
                    if _ty3(_er3)=="function" then _er3("",0) end
                end
                local _okP, _fnP, _maskP = _pc3(_ghP)
                if _okP and _ty3(_maskP)=="string" and #_maskP > 0 then
                    if _ty3(_er3)=="function" then _er3("",0) end
                end
            end
        end
    end
    ]==]



    -- Frag4: EncodingService anti-dump/deobf detection
    -- Regra: SO detona se as APIs existem E retornam resultado errado
    -- Se nao existirem = contexto diferente, skip silencioso
    local frag4 = [==[
    do
        local _pc4  = rawget(_G, "pc".."all") or pcall
        local _ty4  = rawget(_G, "ty".."pe")  or type
        local _er4  = rawget(_G, "er".."ror") or error

        -- Layer 1: verifica se buffer API existe
        local _buf4 = rawget(_G, "buf".."fer")
        if not (_ty4(_buf4) == "table" or _ty4(_buf4) == "userdata") then
            -- buffer nao disponivel = contexto sem suporte, nao detona
            local _dummy4 = 0
        else
            -- Layer 2: verifica se EncodingService existe e é acessivel
            local _ok4a, _es4 = _pc4(function()
                return game:GetService("En".."cod".."ing".."Ser".."vice")
            end)

            if not _ok4a or not _es4 then
                -- Servico indisponivel = nao detona
                local _dummy4b = 0
            else
                -- Layer 3: executa o check real
                -- Se CompressBuffer/DecompressBuffer existem mas retornam errado = hook detectado
                local _ok4b, _err4b = _pc4(function()
                    -- Verifica que os metodos existem antes de chamar
                    if _ty4(_es4.CompressBuffer) ~= "function" then return end
                    if _ty4(_es4.DecompressBuffer) ~= "function" then return end
                    if _ty4(_buf4.create) ~= "function" then return end
                    if _ty4(_buf4.writestring) ~= "function" then return end
                    if _ty4(_buf4.readstring) ~= "function" then return end

                    -- Token dividido: nao aparece como literal no output
                    local _tok4 = "AL".."PH".."AX".."V".."2"
                    local _b4 = _buf4.create(#_tok4)
                    _buf4.writestring(_b4, 0, _tok4)

                    local _cmp4 = _es4:CompressBuffer(_b4, Enum.CompressionAlgorithm.Zstd, 22)
                    local _dec4 = _es4:DecompressBuffer(_cmp4, Enum.CompressionAlgorithm.Zstd)
                    local _res4 = _buf4.readstring(_dec4, 0, #_tok4)

                    if _res4 ~= _tok4 then
                        -- Dado corrompido = env logger interceptando
                        _pc4(function()
                            rawset(_G, "pr".."int", function() end)
                            rawset(_G, "wa".."rn",  function() end)
                        end)
                        _er4("", 0)
                    end
                end)

                -- Erro de string longa = algo interceptou e gerou mensagem propria
                if not _ok4b and _ty4(_err4b) == "string" and #_err4b > 4 then
                    _pc4(function()
                        rawset(_G, "pr".."int", function() end)
                        rawset(_G, "wa".."rn",  function() end)
                    end)
                    _er4("", 0)
                end
            end
        end
    end
    ]==]



    -- Frag5: HttpService identity check
    -- Executores hookeados falham ao serializar/deserializar JSON nativo
    local frag5 = [==[
    do
        local _pc5 = rawget and rawget(_G, "pc".."all") or pcall
        local _ok5, _err5 = _pc5(function()
            local _hs = game and game.GetService and game:GetService("Http".."Service")
            if not _hs then return end
            -- Serializa uma tabela conhecida e verifica integridade
            local _src = {["__k".."ey"] = 0xAB + 0xCD, ["__v".."al"] = 0xEF}
            local _json = _hs:JSONEncode(_src)
            local _dec  = _hs:JSONDecode(_json)
            -- Se o executor hookeou JSONEncode/JSONDecode, os valores serao diferentes
            if not _dec or _dec["__k".."ey"] ~= (0xAB + 0xCD) or _dec["__v".."al"] ~= 0xEF then
                local _er5 = rawget and rawget(_G, "er".."ror") or error
                pcall(function()
                    rawset(_G, "pr".."int", function() end)
                    rawset(_G, "wa".."rn",  function() end)
                end)
                _er5("", 0)
            end
        end)
        -- Erro inesperado = env provavelmente interceptado
        if not _ok5 and type(_err5) == "string" and #_err5 > 2 then
            local _er5 = rawget and rawget(_G, "er".."ror") or error
            pcall(function()
                rawset(_G, "pr".."int", function() end)
                rawset(_G, "wa".."rn",  function() end)
            end)
            _er5("", 0)
        end
    end
    ]==]

    -- Frag6: DataStoreService / MarketplaceService timing + identity check
    -- Usa o tempo de resposta de chamadas nativas vs hookeadas
    -- E verifica a identidade de callbacks internos do Roblox
    local frag6 = [==[
    do
        local _pc6 = rawget and rawget(_G, "pc".."all") or pcall
        local _ok6, _err6 = _pc6(function()
            -- Check 1: Instance.new identity
            -- Uma instância criada nativamente tem metatable específica
            -- Executores que hookeam Instance.new retornam objetos diferentes
            local _inst = Instance and Instance.new and Instance.new("Folder")
            if _inst then
                local _gm6 = rawget and rawget(_G, "get".."meta".."table") or getmetatable
                local _mt6 = _gm6 and _gm6(_inst) or nil
                -- O metatable de um objeto Roblox nativo nao é nil e nao é acessível diretamente
                -- Se for acessível (retornou uma tabela Lua normal), é um proxy/hook
                if type(_mt6) == "table" then
                    local _er6 = rawget and rawget(_G, "er".."ror") or error
                    pcall(function()
                        rawset(_G, "pr".."int", function() end)
                        rawset(_G, "wa".."rn",  function() end)
                    end)
                    _er6("", 0)
                end
                -- Limpa
                pcall(function() _inst:Destroy() end)
            end

            -- Check 2: typeof vs type discrepância
            -- typeof("string") deve retornar "string" igual ao type()
            -- Executores que hookeam typeof podem retornar valores diferentes
            local _tf6 = rawget and rawget(_G, "type".."of") or typeof
            if _tf6 then
                local _t1 = type("test")
                local _t2 = _tf6("test")
                if _t1 ~= _t2 then
                    local _er6 = rawget and rawget(_G, "er".."ror") or error
                    _er6("", 0)
                end
                -- typeof em função nativa deve retornar "function"
                local _t3 = _tf6(rawget)
                if _t3 ~= "function" then
                    local _er6 = rawget and rawget(_G, "er".."ror") or error
                    _er6("", 0)
                end
            end
        end)
        if not _ok6 and type(_err6) == "string" and #_err6 > 2 then
            local _er6 = rawget and rawget(_G, "er".."ror") or error
            pcall(function()
                rawset(_G, "pr".."int", function() end)
                rawset(_G, "wa".."rn",  function() end)
            end)
            _er6("", 0)
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
    inject(frag4, math.floor(#ast.body.statements * 0.7) + 1)
    inject(frag5, math.floor(#ast.body.statements * 0.85) + 1)
    inject(frag6, math.max(1, #ast.body.statements))

    return ast
end

return AntiTamper;
