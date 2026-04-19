local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local Scope    = require("prometheus.scope");
local visitast = require("prometheus.visitast");
local AstKind  = Ast.AstKind;

local MinifyElite = Step:extend();
MinifyElite.Name = "Minify Elite";
MinifyElite.Description = "Dead code + number scramble. Sem string poly para evitar bugs.";
MinifyElite.SettingsDescriptor = {
    DeadDensity = { type = "number", default = 0.5 },
    NumScramble = { type = "number", default = 0.6 },
};

function MinifyElite:init(settings)
    settings         = settings or {}
    self.DeadDensity = settings.DeadDensity or 0.5
    self.NumScramble = settings.NumScramble  or 0.6
end

-- Assinaturas verificadas em ast.lua:
-- DoStatement(body)
-- WhileStatement(body, condition, scope)
-- RepeatStatement(condition, body, scope)
-- IfStatement(condition, body, elseifs, elsebody)
function MinifyElite:dead(scope)
    local s = math.random(1, 5)
    if s == 1 then
        return Ast.DoStatement(Ast.Block({}, Scope:new(scope)))
    elseif s == 2 then
        local i = Scope:new(scope)
        return Ast.IfStatement(Ast.BooleanExpression(false),
            Ast.Block({}, i), {}, nil)
    elseif s == 3 then
        local v = scope:addVariable()
        return Ast.LocalVariableDeclaration(scope, {v}, {Ast.NilExpression()})
    elseif s == 4 then
        local i = Scope:new(scope)
        -- WhileStatement: body PRIMEIRO, condition SEGUNDO
        return Ast.WhileStatement(
            Ast.Block({}, i),
            Ast.BooleanExpression(false),
            scope)
    else
        local i = Scope:new(scope)
        local v = i:addVariable()
        -- RepeatStatement: condition PRIMEIRO, body SEGUNDO
        return Ast.RepeatStatement(
            Ast.BooleanExpression(true),
            Ast.Block({Ast.LocalVariableDeclaration(i, {v}, {Ast.NilExpression()})}, i),
            scope)
    end
end

function MinifyElite:scramble(n)
    local s = math.random(1, 3)
    local e
    if s == 1 then
        local k = math.random(10, 500)
        e = Ast.SubExpression(Ast.NumberExpression(n + k), Ast.NumberExpression(k))
    elseif s == 2 then
        local k = math.random(1, 127)
        e = Ast.AddExpression(Ast.NumberExpression(n - k), Ast.NumberExpression(k))
    else
        local k = math.random(1, 9999)
        e = Ast.AddExpression(Ast.NumberExpression(n),
            Ast.MulExpression(Ast.NumberExpression(k), Ast.NumberExpression(0)))
    end
    e.__me = true
    return e
end

function MinifyElite:apply(ast)
    -- Dead code injection
    local targets = {}
    visitast(ast, nil, function(node, data)
        if node.kind ~= AstKind.Block then return end
        if node.__meDead then return end
        local n = #node.statements
        if n < 2 or n > 45 then return end
        if math.random() > self.DeadDensity then return end
        node.__meDead = true
        table.insert(targets, {block = node, scope = data.scope})
    end)

    for _, t in ipairs(targets) do
        for _ = 1, math.random(2, 3) do
            local ok, d = pcall(function() return self:dead(t.scope) end)
            if ok and d then
                table.insert(t.block.statements,
                    math.random(1, #t.block.statements + 1), d)
            end
        end
    end

    -- Number scramble
    visitast(ast, nil, function(node, data)
        if node.kind == AstKind.NumberExpression and not node.__me then
            local v = node.value
            if type(v) == "number" and v == math.floor(v)
            and v ~= 0 and math.abs(v) < 10000
            and math.random() < self.NumScramble then
                node.__me = true
                local ok, e = pcall(function() return self:scramble(v) end)
                if ok and e then return e end
            end
        end
    end)

    return ast
end

return MinifyElite;
