local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");

local OpaquePredicates = Step:extend();
OpaquePredicates.Name = "Opaque Predicates";
OpaquePredicates.SettingsDescriptor = {
    Treshold = { type="number", default=0.2 }
};
function OpaquePredicates:init(settings)
    settings = settings or {}
    self.Treshold = settings.Treshold or 0.2
end

-- Mix of arithmetic (can't be folded away) and select/rawequal (runtime)
local function alwaysTrue(scope)
    local s = math.random(1, 6)
    local a = math.random(2, 50)
    local b = math.random(2, 50)
    if s == 1 then
        -- select("#", ...) always returns count >= 0  →  select("#") >= 0
        return Ast.NotEqualsExpression(
            Ast.FunctionCallExpression(
                Ast.VariableExpression(scope:resolveGlobal("select")),
                {Ast.StringExpression("#")}
            ),
            Ast.NumberExpression(-1)
        )
    elseif s == 2 then
        -- type(rawget) == "function"
        return Ast.EqualsExpression(
            Ast.FunctionCallExpression(
                Ast.VariableExpression(scope:resolveGlobal("type")),
                {Ast.VariableExpression(scope:resolveGlobal("rawget"))}
            ),
            Ast.StringExpression("function")
        )
    elseif s == 3 then
        -- rawequal(type, type) → true
        return Ast.FunctionCallExpression(
            Ast.VariableExpression(scope:resolveGlobal("rawequal")),
            {
                Ast.VariableExpression(scope:resolveGlobal("type")),
                Ast.VariableExpression(scope:resolveGlobal("type"))
            }
        )
    elseif s == 4 then
        -- (a + b) - b == a
        return Ast.EqualsExpression(
            Ast.SubExpression(
                Ast.AddExpression(Ast.NumberExpression(a), Ast.NumberExpression(b)),
                Ast.NumberExpression(b)
            ),
            Ast.NumberExpression(a)
        )
    elseif s == 5 then
        -- type(pcall) ~= "table"
        return Ast.NotEqualsExpression(
            Ast.FunctionCallExpression(
                Ast.VariableExpression(scope:resolveGlobal("type")),
                {Ast.VariableExpression(scope:resolveGlobal("pcall"))}
            ),
            Ast.StringExpression("table")
        )
    else
        -- a * 1 == a
        return Ast.EqualsExpression(
            Ast.MulExpression(Ast.NumberExpression(a), Ast.NumberExpression(1)),
            Ast.NumberExpression(a)
        )
    end
end

local function alwaysFalse(scope)
    local a = math.random(2, 50)
    local s = math.random(1, 3)
    if s == 1 then
        -- rawequal(rawget, rawset) → false
        return Ast.FunctionCallExpression(
            Ast.VariableExpression(scope:resolveGlobal("rawequal")),
            {
                Ast.VariableExpression(scope:resolveGlobal("rawget")),
                Ast.VariableExpression(scope:resolveGlobal("rawset"))
            }
        )
    elseif s == 2 then
        -- type(pcall) == "table" → false
        return Ast.EqualsExpression(
            Ast.FunctionCallExpression(
                Ast.VariableExpression(scope:resolveGlobal("type")),
                {Ast.VariableExpression(scope:resolveGlobal("pcall"))}
            ),
            Ast.StringExpression("table")
        )
    else
        return Ast.EqualsExpression(
            Ast.NumberExpression(a),
            Ast.NumberExpression(a + 1)
        )
    end
end

function OpaquePredicates:apply(ast, pipeline)
    local mods = {}
    visitast(ast, nil, function(node, data)
        if node.kind == Ast.AstKind.Block
        and #node.statements > 0
        and not node.isOpaqueModified then
            node.isOpaqueModified = true
            if math.random() <= self.Treshold then
                local idx  = math.random(1, #node.statements)
                local stmt = node.statements[idx]
                if stmt.kind == Ast.AstKind.ReturnStatement
                or stmt.kind == Ast.AstKind.BreakStatement then return end
                table.insert(mods, {node=node, idx=idx, stmt=stmt, scope=data.scope})
            end
        end
    end)

    for _, m in ipairs(mods) do
        local ok, cond = pcall(alwaysTrue, m.scope)
        if not ok then cond = Ast.BooleanExpression(true) end
        local realBlock = Ast.Block({m.stmt}, m.scope)
        local deadBlock = Ast.Block({
            Ast.LocalVariableDeclaration(m.scope,
                {m.scope:addVariable()},
                {Ast.NumberExpression(math.random(1,9999))}
            )
        }, m.scope)
        m.node.statements[m.idx] = Ast.IfStatement(cond, realBlock, {}, deadBlock)
    end

    return ast
end

return OpaquePredicates;
