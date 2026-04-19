local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");
local util     = require("prometheus.util");
local Scope    = require("prometheus.scope");
local AstKind  = Ast.AstKind;

local ControlFlowFlattening = Step:extend();
ControlFlowFlattening.Name = "Control Flow Flattening";

function ControlFlowFlattening:init(settings)
    settings           = settings or {}
    self.Treshold      = settings.Treshold      or 0.75
    self.MinStatements = settings.MinStatements  or 3
    self.MaxStatements = settings.MaxStatements  or 20
    self.keyA = math.random(1, 50) * 2 + 1
    self.keyB = math.random(1000, 99999)
    self.keyM = math.random(100003, 999983)
    self.stateMask = math.random(10000, 500000)
end

function ControlFlowFlattening:mix(v)
    return ((v * self.keyA) + self.keyB) % self.keyM
end

function ControlFlowFlattening:mix3(v)
    return self:mix(self:mix(self:mix(v)))
end

function ControlFlowFlattening:mix3Ast(varExpr)
    local function m(e)
        return Ast.ModExpression(
            Ast.AddExpression(
                Ast.MulExpression(e, Ast.NumberExpression(self.keyA)),
                Ast.NumberExpression(self.keyB)
            ),
            Ast.NumberExpression(self.keyM)
        )
    end
    return m(m(m(varExpr)))
end

local function safeSplit(n)
    local k = math.random(1, 300)
    return Ast.AddExpression(
        Ast.NumberExpression(n - k),
        Ast.NumberExpression(k)
    )
end

function ControlFlowFlattening:flatten(block, scope)
    local stmts = block.statements
    local n     = #stmts

    local stVar  = scope:addVariable()
    local mixVar = scope:addVariable()

    local ids = {}
    for i = 1, n do
        ids[i] = math.random(100, 9999) + self.stateMask
    end
    local terminal = math.random(10000, 99999) + self.stateMask + 777

    -- Fake states with real side effect: modify a shared counter
    local counterVar = scope:addVariable()
    local fakeCount  = math.random(2, 4)
    local fakeIds    = {}
    for i = 1, fakeCount do
        fakeIds[i] = math.random(100, 9999) + self.stateMask + 3
    end

    local chunks = {}

    -- Real chunks
    for i, stat in ipairs(stmts) do
        local nextId = (i < n) and ids[i+1] or terminal
        local k      = math.random(1, 200)
        local jumpStat = Ast.AssignmentStatement(
            {Ast.AssignmentVariable(scope, stVar)},
            {Ast.AddExpression(Ast.NumberExpression(nextId - k), Ast.NumberExpression(k))}
        )
        local mixUpdate = Ast.AssignmentStatement(
            {Ast.AssignmentVariable(scope, mixVar)},
            {self:mix3Ast(Ast.VariableExpression(scope, stVar))}
        )
        local cs = Scope:new(scope)
        chunks[#chunks+1] = {
            id    = ids[i],
            mixId = self:mix3(ids[i]),
            body  = Ast.Block({stat, jumpStat, mixUpdate}, cs)
        }
    end

    -- Fake chunks (increment counter = real side effect, indistinguishable)
    for i = 1, fakeCount do
        local fs  = Scope:new(scope)
        fs:addReferenceToHigherScope(scope, counterVar)
        local fv  = fs:addVariable()
        local fakeNext = fakeIds[math.random(#fakeIds)]
        local fk = math.random(1, 200)
        chunks[#chunks+1] = {
            id    = fakeIds[i],
            mixId = self:mix3(fakeIds[i]),
            body  = Ast.Block({
                Ast.AssignmentStatement(
                    {Ast.AssignmentVariable(scope, counterVar)},
                    {Ast.AddExpression(Ast.VariableExpression(scope, counterVar), Ast.NumberExpression(1))}
                ),
                Ast.LocalVariableDeclaration(fs, {fv}, {
                    Ast.ModExpression(
                        Ast.MulExpression(Ast.VariableExpression(scope, counterVar), Ast.NumberExpression(math.random(3,17))),
                        Ast.NumberExpression(self.keyM)
                    )
                }),
                Ast.AssignmentStatement(
                    {Ast.AssignmentVariable(scope, stVar)},
                    {Ast.AddExpression(Ast.NumberExpression(fakeNext - fk), Ast.NumberExpression(fk))}
                ),
                Ast.AssignmentStatement(
                    {Ast.AssignmentVariable(scope, mixVar)},
                    {self:mix3Ast(Ast.VariableExpression(scope, stVar))}
                )
            }, fs)
        }
    end

    util.shuffle(chunks)

    local rootIf = nil
    for _, chunk in ipairs(chunks) do
        local ck   = math.min(chunk.mixId, 300)
        if ck < 1 then ck = 1 end
        local cond = Ast.EqualsExpression(
            Ast.VariableExpression(scope, mixVar),
            Ast.AddExpression(Ast.NumberExpression(chunk.mixId - ck), Ast.NumberExpression(ck))
        )
        if not rootIf then
            rootIf = Ast.IfStatement(cond, chunk.body, {}, nil)
        else
            table.insert(rootIf.elseIfs, {condition=cond, block=chunk.body})
        end
    end
    if not rootIf then return end

    local termMix = self:mix3(terminal)
    local tk = math.min(termMix, 300)
    if tk < 1 then tk = 1 end
    local whileCond = Ast.NotEqualsExpression(
        Ast.VariableExpression(scope, mixVar),
        Ast.AddExpression(Ast.NumberExpression(termMix - tk), Ast.NumberExpression(tk))
    )
    local whileLoop = Ast.WhileStatement(
        Ast.Block({rootIf}, Scope:new(scope)),
        whileCond, scope
    )

    local ik = math.min(ids[1], 200)
    if ik < 1 then ik = 1 end
    block.statements = {
        Ast.LocalVariableDeclaration(scope, {counterVar}, {Ast.NumberExpression(0)}),
        Ast.LocalVariableDeclaration(scope, {stVar}, {
            Ast.AddExpression(Ast.NumberExpression(ids[1] - ik), Ast.NumberExpression(ik))
        }),
        Ast.LocalVariableDeclaration(scope, {mixVar}, {
            self:mix3Ast(Ast.VariableExpression(scope, stVar))
        }),
        whileLoop
    }
end

function ControlFlowFlattening:apply(ast)
    local targets = {}
    visitast(ast, nil, function(node, data)
        if node.kind ~= AstKind.Block then return end
        if node.isCffModified then return end
        if #node.statements < self.MinStatements then return end
        if #node.statements > self.MaxStatements then return end
        if math.random() > self.Treshold then return end
        local skip = false
        for _, s in ipairs(node.statements) do
            if s.kind == AstKind.ReturnStatement or s.kind == AstKind.BreakStatement
            or s.kind == AstKind.WhileStatement or s.kind == AstKind.LocalVariableDeclaration then
                skip = true; break
            end
        end
        if skip then return end
        node.isCffModified = true
        table.insert(targets, {block=node, scope=data.scope})
    end)
    for _, t in ipairs(targets) do
        pcall(function() self:flatten(t.block, t.scope) end)
    end
    return ast
end

return ControlFlowFlattening;
