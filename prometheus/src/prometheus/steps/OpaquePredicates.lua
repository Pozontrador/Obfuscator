local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");

local OpaquePredicates = Step:extend();
OpaquePredicates.Name = "Opaque Predicates";
OpaquePredicates.SettingsDescriptor = {
    Treshold = { type="number", default=0.4 }
};
function OpaquePredicates:init(settings)
    settings = settings or {}
    self.Treshold = settings.Treshold or 0.4
end

-- Estratégia: usar pcall para definir uma variável local
-- O deobfuscador NÃO rastreia o estado de variáveis modificadas dentro de pcall
-- então não consegue saber se _r é true ou false depois do pcall
--
-- Estrutura gerada:
--   local _r = false
--   pcall(function() _r = not not rawget end)
--   if _r then [REAL CODE] else [DEAD CODE] end

function OpaquePredicates:apply(ast, pipeline)
    local modifications = {}

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
                table.insert(modifications, {
                    blockNode = node, index = idx,
                    statement = stmt, scope = data.scope
                })
            end
        end
    end)

    for _, mod in ipairs(modifications) do
        local scope = mod.scope
        local s = math.random(1, 4)

        -- Variável local que recebe valor dentro de pcall
        local rVar = scope:addVariable()

        -- pcall closure scope
        local pcScope = Scope:new(scope)
        pcScope:addReferenceToHigherScope(scope, rVar)

        local assignVal
        if s == 1 then
            -- _r = not not rawget  (rawget é truthy, logo true)
            assignVal = Ast.NotExpression(
                Ast.NotExpression(Ast.VariableExpression(scope:resolveGlobal("rawget")))
            )
        elseif s == 2 then
            -- _r = not not rawset
            assignVal = Ast.NotExpression(
                Ast.NotExpression(Ast.VariableExpression(scope:resolveGlobal("rawset")))
            )
        elseif s == 3 then
            -- _r = not not pcall
            assignVal = Ast.NotExpression(
                Ast.NotExpression(Ast.VariableExpression(scope:resolveGlobal("pcall")))
            )
        else
            -- _r = not not setmetatable
            assignVal = Ast.NotExpression(
                Ast.NotExpression(Ast.VariableExpression(scope:resolveGlobal("setmetatable")))
            )
        end

        -- pcall(function() _r = <val> end)
        local pcallFn = Ast.FunctionLiteralExpression({},
            Ast.Block({
                Ast.AssignmentStatement(
                    {Ast.AssignmentVariable(scope, rVar)},
                    {assignVal}
                )
            }, pcScope)
        )
        local pcallStmt = Ast.FunctionCallStatement(
            Ast.VariableExpression(scope:resolveGlobal("pcall")),
            {pcallFn}
        )

        -- real block + dead block
        local realBlock = Ast.Block({mod.statement}, scope)
        local deadScope = Scope:new(scope)
        local deadBlock = Ast.Block({
            Ast.AssignmentStatement(
                {Ast.AssignmentVariable(scope:resolveGlobal("_x_"..tostring(math.random(1e5,9e5))))},
                {Ast.NumberExpression(math.random(1,9999))}
            )
        }, deadScope)

        -- local _r = false; pcall(...); if _r then real else dead end
        local localDecl = Ast.LocalVariableDeclaration(
            scope, {rVar}, {Ast.BooleanExpression(false)}
        )
        local ifStmt = Ast.IfStatement(
            Ast.VariableExpression(scope, rVar),
            realBlock, {}, deadBlock
        )

        -- Replace single statement with 3: local, pcall, if
        local block = mod.blockNode
        block.statements[mod.index] = ifStmt
        table.insert(block.statements, mod.index, pcallStmt)
        table.insert(block.statements, mod.index, localDecl)
    end

    return ast
end

return OpaquePredicates;
