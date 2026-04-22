local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");
local util     = require("prometheus.util");

local ConstantArray = Step:extend();
ConstantArray.Name        = "Constant Array";
ConstantArray.SettingsDescriptor = {
    Treshold    = { type="number",  default=1,     min=0, max=1 },
    StringsOnly = { type="boolean", default=false },
    Shuffle     = { type="boolean", default=true  },
}

function ConstantArray:init(settings)
    settings         = settings or {}
    self.Treshold    = settings.Treshold    or 1
    self.StringsOnly = settings.StringsOnly or false
    self.Shuffle     = settings.Shuffle ~= false
    self.fixedOffset = math.random(50, 500)
    self.offsetK1    = math.random(1, self.fixedOffset - 1)
    self.offsetK2    = self.fixedOffset - self.offsetK1
    -- Per-build additive cipher for integer constants
    self.numKey      = math.random(10000, 9999999)  -- much larger keyspace
    -- Per-build multiplicative index scrambler
    -- stored_pos = (real_pos * mA + mB) % count — hides array structure
    self.mA = math.random(3, 97) * 2 + 1
    self.mB = math.random(10, 999)
end

function ConstantArray:scrambleIndex(i, n)
    if n <= 0 then return i end
    return ((i - 1) * self.mA + self.mB) % n + 1
end

function ConstantArray:createArray()
    local entries = {}
    for i, v in ipairs(self.constants) do
        -- Encode integers with additive cipher: store (v + numKey)
        -- Decoder subtracts numKey at runtime
        if type(v) == "number" and v == math.floor(v)
        and math.abs(v) < 2^23 then
            local encoded = v + self.numKey
            -- Split encoded value into two parts to hide it further
            local noise = math.random(1, 500)
            local node = Ast.SubExpression(
                Ast.NumberExpression(encoded + noise),
                Ast.NumberExpression(noise)
            )
            node.__ignoreNum = true
            entries[i] = Ast.TableEntry(node)
        else
            entries[i] = Ast.TableEntry(Ast.ConstantNode(v))
        end
    end
    return Ast.TableConstructorExpression(entries)
end

function ConstantArray:indexing(index, data)
    -- Use pre-loaded decoder alias if available, else fall back to wrapperTable[1]
    if self.decoderAlias then
        data.scope:addReferenceToHigherScope(self.rootScope, self.decoderAlias)
        return Ast.FunctionCallExpression(
            Ast.VariableExpression(self.rootScope, self.decoderAlias),
            { Ast.NumberExpression(index + self.fixedOffset) }
        )
    end
    data.scope:addReferenceToHigherScope(self.rootScope, self.wrapperTable)
    return Ast.FunctionCallExpression(
        Ast.IndexExpression(
            Ast.VariableExpression(self.rootScope, self.wrapperTable),
            Ast.NumberExpression(1)
        ),
        { Ast.NumberExpression(index + self.fixedOffset) }
    )
end

function ConstantArray:getConstant(value, data)
    if value == nil then return Ast.ConstantNode(nil) end
    if self.lookup[value] then return self:indexing(self.lookup[value], data) end
    local idx = #self.constants + 1
    self.constants[idx] = value
    self.lookup[value]  = idx
    return self:indexing(idx, data)
end

function ConstantArray:addConstant(value)
    if value == nil or self.lookup[value] then return end
    local idx = #self.constants + 1
    self.constants[idx] = value
    self.lookup[value]  = idx
end

function ConstantArray:apply(ast, pipeline)
    self.rootScope    = ast.body.scope
    self.arrId        = self.rootScope:addVariable()
    self.constants    = {}
    self.lookup       = {}
    self.wrapperTable = self.rootScope:addVariable()
    -- Pre-allocate decoderAlias so indexing() can use it from the start
    self.decoderAlias = self.rootScope:addVariable()

    visitast(ast, nil, function(node, data)
        if math.random() <= self.Treshold then
            if node.kind == Ast.AstKind.StringExpression then
                node.__apply_constant_array = true
                self:addConstant(node.value)
            elseif not self.StringsOnly and node.isConstant and node.value ~= nil then
                node.__apply_constant_array = true
                self:addConstant(node.value)
            end
        end
    end)

    if self.Shuffle and #self.constants > 0 then
        self.constants = util.shuffle(self.constants)
        self.lookup = {}
        for i, v in ipairs(self.constants) do self.lookup[v] = i end
    end

    visitast(ast, nil, function(node, data)
        if node.__apply_constant_array then
            node.__apply_constant_array = nil
            return self:getConstant(node.value, data)
        end
    end)

    if #self.constants == 0 then return ast end

    local funcScope = require("prometheus.scope"):new(self.rootScope)
    funcScope:addReferenceToHigherScope(self.rootScope, self.arrId)
    local arg = funcScope:addVariable()

    -- Offset split into two parts, multiplied by 1 to obscure the simple addition
    local _ok1 = self.offsetK1
    local _ok2 = self.offsetK2
    local offsetExpr = Ast.AddExpression(
        Ast.MulExpression(Ast.NumberExpression(_ok1), Ast.NumberExpression(1)),
        Ast.AddExpression(
            Ast.NumberExpression(_ok2 - 1),
            Ast.NumberExpression(1)
        )
    )
    -- Decoder: reads arr[arg-offset], then subtracts numKey if the value is a number
    -- function(arg)
    --   local _v = arr[arg - (k1+k2)]
    --   if type(_v) == "number" then return _v - numKey else return _v end
    -- end
    local vVal    = funcScope:addVariable()
    local ifScope = require("prometheus.scope"):new(funcScope)

    local arrRead = Ast.IndexExpression(
        Ast.VariableExpression(self.rootScope, self.arrId),
        Ast.SubExpression(Ast.VariableExpression(funcScope, arg), offsetExpr)
    )
    local decodeIfStmt = Ast.IfStatement(
        Ast.EqualsExpression(
            Ast.FunctionCallExpression(
                Ast.VariableExpression(funcScope:resolveGlobal("type")),
                {Ast.VariableExpression(funcScope, vVal)}
            ),
            Ast.StringExpression("number")
        ),
        Ast.Block({
            Ast.ReturnStatement({
                Ast.SubExpression(
                    Ast.VariableExpression(funcScope, vVal),
                    Ast.NumberExpression(self.numKey)
                )
            })
        }, ifScope),
        {}, nil
    )

    local funcLiteral = Ast.FunctionLiteralExpression(
        {Ast.VariableExpression(funcScope, arg)},
        Ast.Block({
            Ast.LocalVariableDeclaration(funcScope, {vVal}, {arrRead}),
            decodeIfStmt,
            Ast.ReturnStatement({Ast.VariableExpression(funcScope, vVal)})
        }, funcScope)
    )

    -- Pre-load the decoder directly as a local function (no wrapper table fingerprint)
    -- decoderAlias was pre-allocated above, just emit the declaration now
    table.insert(ast.body.statements, 1, Ast.LocalVariableDeclaration(
        self.rootScope, {self.decoderAlias}, {funcLiteral}
    ))
    -- wrapperTable still declared for compatibility but empty
    table.insert(ast.body.statements, 1, Ast.LocalVariableDeclaration(
        self.rootScope, {self.wrapperTable}, {Ast.TableConstructorExpression({})}
    ))
    table.insert(ast.body.statements, 1, Ast.LocalVariableDeclaration(
        self.rootScope, {self.arrId}, {self:createArray()}
    ))

    -- Update all indexing calls to use the alias directly
    self.decoderAlias = decoderAlias

    return ast
end

return ConstantArray;
