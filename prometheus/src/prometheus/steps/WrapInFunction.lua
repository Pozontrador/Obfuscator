local Step  = require("prometheus.step");
local Ast   = require("prometheus.ast");
local Scope = require("prometheus.scope");

local WrapInFunction = Step:extend();
WrapInFunction.Name = "Wrap in Function";
WrapInFunction.SettingsDescriptor = {
    Iterations = { type="number", default=1, min=1, max=nil }
};
function WrapInFunction:init(settings) end

function WrapInFunction:apply(ast)
    for i = 1, self.Iterations do
        local body = ast.body
        local scope = Scope:new(ast.globalScope)
        body.scope:setParent(scope)

        -- Alternate between two safe styles per iteration
        if i % 2 == 0 then
            -- Style A: indirect via table {fn}[1](...)
            local wVar = scope:addVariable()
            local fn   = Ast.FunctionLiteralExpression({Ast.VarargExpression()}, body)
            ast.body   = Ast.Block({
                Ast.LocalVariableDeclaration(scope, {wVar}, {
                    Ast.TableConstructorExpression({Ast.TableEntry(fn)})
                }),
                Ast.ReturnStatement({
                    Ast.FunctionCallExpression(
                        Ast.IndexExpression(
                            Ast.VariableExpression(scope, wVar),
                            Ast.NumberExpression(1)
                        ),
                        {Ast.VarargExpression()}
                    )
                })
            }, scope)
        else
            -- Style B: original safe wrap
            ast.body = Ast.Block({
                Ast.ReturnStatement({
                    Ast.FunctionCallExpression(
                        Ast.FunctionLiteralExpression({Ast.VarargExpression()}, body),
                        {Ast.VarargExpression()}
                    )
                })
            }, scope)
        end
    end
end

return WrapInFunction;
