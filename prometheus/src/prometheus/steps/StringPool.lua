-- StringPool.lua — Pool único de strings, lido uma vez no início
-- Todas as StringExpression viram _sp[idx] onde _sp é uma local
-- Zero overhead em runtime: local array access = mais rápido que global lookup
local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");
local util     = require("prometheus.util");
local AstKind  = Ast.AstKind;

local StringPool = Step:extend();
StringPool.Name = "String Pool";
StringPool.Description = "Pool unico de strings pre-carregado em local.";
StringPool.SettingsDescriptor = {
    Treshold = { type = "number", default = 0.8 },
};

function StringPool:init(settings)
    settings = settings or {}
    self.Treshold = settings.Treshold or 0.8
end

function StringPool:apply(ast)
    local rootScope = ast.body.scope
    local pool   = {}
    local pmap   = {}

    -- Coleta strings elegíveis
    visitast(ast, nil, function(node, data)
        if node.kind ~= AstKind.StringExpression then return end
        if node.__spDone then return end
        if math.random() > self.Treshold then return end
        local s = node.value
        -- Só strings curtas-médias, não vazias
        if #s == 0 or #s > 80 then return end
        if not pmap[s] then
            pmap[s] = #pool + 1
            pool[#pool+1] = s
        end
    end)

    if #pool == 0 then return ast end

    -- Embaralha para dificultar mapeamento por posição
    util.shuffle(pool)
    local idx = {}
    for i, s in ipairs(pool) do idx[s] = i end

    -- Cria variável do pool
    local vPool = rootScope:addVariable()

    -- local _sp = {"str1", "str2", ...}
    local entries = {}
    for _, s in ipairs(pool) do
        local e = Ast.TableEntry(Ast.StringExpression(s))
        e.__spDone = true
        entries[#entries+1] = e
    end

    local poolDecl = Ast.LocalVariableDeclaration(rootScope, {vPool}, {
        Ast.TableConstructorExpression(entries)
    })
    table.insert(ast.body.statements, 1, poolDecl)

    -- Substitui strings por _sp[idx]
    visitast(ast, nil, function(node, data)
        if node.kind ~= AstKind.StringExpression then return end
        if node.__spDone then return end
        local s = node.value
        local i = idx[s]
        if not i then return end
        node.__spDone = true
        data.scope:addReferenceToHigherScope(rootScope, vPool)
        local access = Ast.IndexExpression(
            Ast.VariableExpression(rootScope, vPool),
            Ast.NumberExpression(i)
        )
        access.__spDone = true
        return access
    end)

    return ast
end

return StringPool;
