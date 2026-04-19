local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");
local Scope    = require("prometheus.scope");

local DeadCodeInjection = Step:extend();
DeadCodeInjection.Name = "Dead Code Injection";
DeadCodeInjection.SettingsDescriptor = {
    Amount = { name="Amount", type="number", default=15 }
};
function DeadCodeInjection:init(settings) end

local function makeJunk(scope)
    local s  = math.random(1, 5)
    local v1 = scope:addVariable()
    local v2 = scope:addVariable()
    local n1 = math.random(1000, 999999)
    local n2 = math.random(1000, 999999)

    if s == 1 then
        -- local _a = N; local _b = _a * M
        return {
            Ast.LocalVariableDeclaration(scope, {v1}, {Ast.NumberExpression(n1)}),
            Ast.LocalVariableDeclaration(scope, {v2}, {
                Ast.MulExpression(Ast.VariableExpression(scope, v1), Ast.NumberExpression(n2))
            })
        }
    elseif s == 2 then
        -- local _a = N; local _b = _a + _a
        return {
            Ast.LocalVariableDeclaration(scope, {v1}, {Ast.NumberExpression(n1)}),
            Ast.LocalVariableDeclaration(scope, {v2}, {
                Ast.AddExpression(Ast.VariableExpression(scope, v1), Ast.VariableExpression(scope, v1))
            })
        }
    elseif s == 3 then
        -- local _a = N; local _b = N - _a (always 0)
        return {
            Ast.LocalVariableDeclaration(scope, {v1}, {Ast.NumberExpression(n1)}),
            Ast.LocalVariableDeclaration(scope, {v2}, {
                Ast.SubExpression(Ast.NumberExpression(n1), Ast.VariableExpression(scope, v1))
            })
        }
    elseif s == 4 then
        -- local _a = N; local _b = _a % 65536
        return {
            Ast.LocalVariableDeclaration(scope, {v1}, {Ast.NumberExpression(n1)}),
            Ast.LocalVariableDeclaration(scope, {v2}, {
                Ast.ModExpression(
                    Ast.MulExpression(Ast.VariableExpression(scope, v1), Ast.NumberExpression(n2)),
                    Ast.NumberExpression(65536)
                )
            })
        }
    else
        -- local _a = true; local _b = not not _a
        return {
            Ast.LocalVariableDeclaration(scope, {v1}, {Ast.BooleanExpression(true)}),
            Ast.LocalVariableDeclaration(scope, {v2}, {
                Ast.NotExpression(Ast.NotExpression(Ast.VariableExpression(scope, v1)))
            })
        }
    end
end

function DeadCodeInjection:apply(ast, pipeline)
    local mods = {}
    visitast(ast, nil, function(node, data)
        if node.kind == Ast.AstKind.Block and #node.statements > 0 then
            if math.random(1, 100) <= self.Amount then
                table.insert(mods, {node = node, scope = data.scope})
            end
        end
    end)
    for _, m in ipairs(mods) do
        local ok, stmts = pcall(makeJunk, m.scope)
        if ok and stmts then
            local pos = math.random(1, #m.node.statements)
            for i = #stmts, 1, -1 do
                table.insert(m.node.statements, pos, stmts[i])
            end
        end
    end
    return ast
end

return DeadCodeInjection;
