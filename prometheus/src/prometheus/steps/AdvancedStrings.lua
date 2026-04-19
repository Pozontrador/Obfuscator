local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local visitast = require("prometheus.visitast");

local AdvancedStrings = Step:extend();
AdvancedStrings.Description = "Transforma strings em concatenações de string.char()";
AdvancedStrings.Name = "Advanced Strings";
AdvancedStrings.SettingsDescriptor = {
    Treshold = { type = "number", default = 1 },
}

function AdvancedStrings:init(settings)
    settings = settings or {}
    self.Treshold = settings.Treshold or 1
end

function AdvancedStrings:apply(ast, pipeline)
    visitast(ast, nil, function(node, data)
        if node.kind == Ast.AstKind.StringExpression and not node.__ignoreAdvanced then
            if math.random() <= self.Treshold then
                local str = node.value
                if #str == 0 or #str > 100 then return node end

                -- Resolve a biblioteca global 'string' corretamente para a AST não crashar
                local stringScope, stringId = data.scope:resolveGlobal("string")
                data.scope:addReferenceToHigherScope(stringScope, stringId)

                local concatNode = nil
                
                for i = 1, #str do
                    local byte = string.byte(str, i)
                    local offset = math.random(10, 250)
                    local operation = math.random(1, 2)
                    
                    local mathExpr
                    if operation == 1 then
                        mathExpr = Ast.AddExpression(Ast.NumberExpression(byte - offset), Ast.NumberExpression(offset))
                    else
                        mathExpr = Ast.SubExpression(Ast.NumberExpression(byte + offset), Ast.NumberExpression(offset))
                    end
                    
                    local charStr = Ast.StringExpression("char")
                    charStr.__ignoreAdvanced = true -- Evita loop infinito no visitast
                    
                    local charCall = Ast.FunctionCallExpression(
                        Ast.IndexExpression(Ast.VariableExpression(stringScope, stringId), charStr),
                        { mathExpr }
                    )
                    
                    if not concatNode then
                        concatNode = charCall
                    else
                        concatNode = Ast.StrCatExpression(concatNode, charCall)
                    end
                end
                
                if concatNode then
                    -- O 'true' no retorno pula a visitação dos nós filhos criados agora
                    return concatNode, true 
                end
            end
        end
    end)
    return ast;
end

return AdvancedStrings;
