-- PackBytecode v2 — decodifica TUDO uma vez no início, acesso O(1)
-- Antes: pos = _decode(42)  ← chamada de função em cada jump = lento
-- Agora: pos = _ids[42]     ← acesso de tabela = O(1), zero overhead
local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");
local AstKind  = Ast.AstKind;

local PackBytecode = Step:extend();
PackBytecode.Name = "Pack Bytecode";
PackBytecode.Description = "Block IDs em string binaria, decodificados uma vez em tabela.";
PackBytecode.SettingsDescriptor = {};

function PackBytecode:init(settings) end

-- Simple RLE compression for byte arrays
local function rleCompress(bytes)
    local out = {}
    local i   = 1
    while i <= #bytes do
        local b   = bytes[i]
        local run = 1
        while i + run <= #bytes and bytes[i + run] == b and run < 127 do
            run = run + 1
        end
        if run >= 3 then
            -- Escape: 0xFF, count, byte
            out[#out+1] = 0xFF
            out[#out+1] = run
            out[#out+1] = b
        else
            for j = 1, run do
                if b == 0xFF then
                    -- Escape literal 0xFF as 0xFF 0x01 0xFF
                    out[#out+1] = 0xFF
                    out[#out+1] = 1
                    out[#out+1] = 0xFF
                else
                    out[#out+1] = b
                end
            end
        end
        i = i + run
    end
    return out
end

function PackBytecode:apply(ast)
    local rootScope = ast.body.scope
    local xorKey    = math.random(1, 255)

    -- Coleta block IDs (numeros >= 100000 em AssignmentStatements)
    local ids     = {}
    local idIndex = {}
    local targets = {}

    visitast(ast, nil, function(node, data)
        if node.kind ~= AstKind.AssignmentStatement then return end
        if not node.lhs or not node.rhs then return end
        if #node.lhs ~= 1 or #node.rhs ~= 1 then return end
        if node.lhs[1].kind ~= AstKind.AssignmentVariable then return end
        local rhs = node.rhs[1]
        if rhs.kind ~= AstKind.NumberExpression then return end
        local v = rhs.value
        if type(v) ~= "number" or v < 100000 or v ~= math.floor(v) then return end
        if not idIndex[v] then
            idIndex[v] = #ids + 1
            ids[#ids+1] = v
        end
        table.insert(targets, {rhs = rhs, id = v})
    end)

    if #ids == 0 then return ast end

    -- Empacota IDs em string (4 bytes little-endian, cifra aditiva)
    local bytes = {}
    for _, id in ipairs(ids) do
        local b0 = id % 256
        local b1 = math.floor(id / 256) % 256
        local b2 = math.floor(id / 65536) % 256
        local b3 = math.floor(id / 16777216) % 256
        bytes[#bytes+1] = (b0 + xorKey) % 256
        bytes[#bytes+1] = (b1 + xorKey + 1) % 256
        bytes[#bytes+1] = (b2 + xorKey + 2) % 256
        bytes[#bytes+1] = (b3 + xorKey + 3) % 256
    end
    local compressed = rleCompress(bytes)
    local strParts = {}
    for _, b in ipairs(compressed) do strParts[#strParts+1] = string.format("\\%d", b) end
    local packedStr = table.concat(strParts)

    -- Variáveis do loader
    local vPacked  = rootScope:addVariable()  -- compressed+encrypted string
    local vKey     = rootScope:addVariable()  -- chave XOR
    local vIds     = rootScope:addVariable()  -- tabela pre-computada
    local vSB      = rootScope:addVariable()  -- string.byte
    local vI       = rootScope:addVariable()  -- loop var
    local vRaw     = rootScope:addVariable()  -- decompressed bytes table
    local vRI      = rootScope:addVariable()  -- rle loop var
    local vRB      = rootScope:addVariable()  -- rle byte
    local vRC      = rootScope:addVariable()  -- rle count

    -- Loop de decodificação (roda UMA VEZ no inicio):
    -- local _ids = {}
    -- for i=1,#_packed,4 do
    --   local base = i
    --   local b0 = (sb(packed,base)   - key     + 256) % 256
    --   local b1 = (sb(packed,base+1) - key - 1 + 512) % 256
    --   local b2 = (sb(packed,base+2) - key - 2 + 512) % 256
    --   local b3 = (sb(packed,base+3) - key - 3 + 512) % 256
    --   _ids[#_ids+1] = b0 + b1*256 + b2*65536 + b3*16777216
    -- end

    local forScope = require("prometheus.scope"):new(rootScope)
    forScope:addReferenceToHigherScope(rootScope, vIds)
    forScope:addReferenceToHigherScope(rootScope, vPacked)
    forScope:addReferenceToHigherScope(rootScope, vKey)
    forScope:addReferenceToHigherScope(rootScope, vSB)

    local vB0 = forScope:addVariable()
    local vB1 = forScope:addVariable()
    local vB2 = forScope:addVariable()
    local vB3 = forScope:addVariable()

    -- Read from decompressed _raw table instead of _packed string
    local function sbAt(offset)
        return Ast.IndexExpression(
            Ast.VariableExpression(rootScope, vRaw),
            Ast.AddExpression(Ast.VariableExpression(forScope, vI), Ast.NumberExpression(offset))
        )
    end

    local function decByte(offset)
        return Ast.ModExpression(
            Ast.AddExpression(
                Ast.SubExpression(
                    sbAt(offset),
                    Ast.AddExpression(Ast.VariableExpression(rootScope, vKey), Ast.NumberExpression(offset))
                ),
                Ast.NumberExpression(512)
            ),
            Ast.NumberExpression(256)
        )
    end

    local forBody = Ast.Block({
        Ast.LocalVariableDeclaration(forScope, {vB0}, {decByte(0)}),
        Ast.LocalVariableDeclaration(forScope, {vB1}, {decByte(1)}),
        Ast.LocalVariableDeclaration(forScope, {vB2}, {decByte(2)}),
        Ast.LocalVariableDeclaration(forScope, {vB3}, {decByte(3)}),
        Ast.AssignmentStatement(
            {Ast.AssignmentIndexing(
                Ast.VariableExpression(rootScope, vIds),
                Ast.AddExpression(
                    Ast.LenExpression(Ast.VariableExpression(rootScope, vIds)),
                    Ast.NumberExpression(1)
                )
            )},
            {Ast.AddExpression(
                Ast.AddExpression(
                    Ast.AddExpression(
                        Ast.VariableExpression(forScope, vB0),
                        Ast.MulExpression(Ast.VariableExpression(forScope, vB1), Ast.NumberExpression(256))
                    ),
                    Ast.MulExpression(Ast.VariableExpression(forScope, vB2), Ast.NumberExpression(65536))
                ),
                Ast.MulExpression(Ast.VariableExpression(forScope, vB3), Ast.NumberExpression(16777216))
            )}
        )
    }, forScope)

    local forLoop = Ast.ForStatement(
        forScope, vI,
        Ast.NumberExpression(1),
        Ast.LenExpression(Ast.VariableExpression(rootScope, vRaw)),
        Ast.NumberExpression(4),
        forBody, rootScope
    )

    -- Injeta no topo
    -- RLE decompressor emitted as Lua inline:
    -- local _raw = {}
    -- for _i=1,#_packed do
    --   local _b = sb(_packed,_i)
    --   if _b==255 then _count=sb(_packed,_i+1); _byte=sb(_packed,_i+2)
    --     for j=1,_count do _raw[#_raw+1]=_byte end; _i=_i+2
    --   else _raw[#_raw+1]=_b end
    -- end
    -- (then XOR decode from _raw instead of _packed)

    local rleScope  = Scope:new(rootScope)
    rleScope:addReferenceToHigherScope(rootScope, vRaw)
    rleScope:addReferenceToHigherScope(rootScope, vSB)
    rleScope:addReferenceToHigherScope(rootScope, vPacked)
    local rleI    = rleScope:addVariable()
    local rleByte = rleScope:addVariable()
    local rleInnerScope = Scope:new(rleScope)
    rleInnerScope:addReferenceToHigherScope(rleScope, rleByte)
    rleInnerScope:addReferenceToHigherScope(rootScope, vRaw)
    rleInnerScope:addReferenceToHigherScope(rootScope, vSB)
    rleInnerScope:addReferenceToHigherScope(rootScope, vPacked)
    rleInnerScope:addReferenceToHigherScope(rleScope, rleI)
    local rleCount  = rleInnerScope:addVariable()
    local rleJ      = rleInnerScope:addVariable()
    local rleJScope = Scope:new(rleInnerScope)
    rleJScope:addReferenceToHigherScope(rootScope, vRaw)
    rleJScope:addReferenceToHigherScope(rleInnerScope, rleByte)

    local appendByte = function(exprByte)
        return Ast.AssignmentStatement(
            {Ast.AssignmentIndexing(
                Ast.VariableExpression(rootScope, vRaw),
                Ast.AddExpression(
                    Ast.LenExpression(Ast.VariableExpression(rootScope, vRaw)),
                    Ast.NumberExpression(1)
                )
            )},
            {exprByte}
        )
    end

    -- Inner RLE expand loop: for _j=1,_count do _raw[#_raw+1]=_byte end
    local expandLoop = Ast.ForStatement(
        rleJScope, rleJ,
        Ast.NumberExpression(1),
        Ast.VariableExpression(rleInnerScope, rleCount),
        Ast.NumberExpression(1),
        Ast.Block({appendByte(Ast.VariableExpression(rleInnerScope, rleByte))}, rleJScope),
        rleInnerScope
    )

    local sbCall3 = function(offset)
        return Ast.FunctionCallExpression(Ast.VariableExpression(rootScope, vSB), {
            Ast.VariableExpression(rootScope, vPacked),
            Ast.AddExpression(Ast.VariableExpression(rleScope, rleI), Ast.NumberExpression(offset))
        })
    end

    -- if byte==255 then expand else append
    local ifScope2 = Scope:new(rleScope)
    local rleIfBody = Ast.Block({
        Ast.LocalVariableDeclaration(rleInnerScope, {rleCount}, {sbCall3(1)}),
        Ast.LocalVariableDeclaration(rleInnerScope, {rleByte},  {sbCall3(2)}),
        expandLoop,
        Ast.AssignmentStatement(
            {Ast.AssignmentVariable(rleScope, rleI)},
            {Ast.AddExpression(Ast.VariableExpression(rleScope, rleI), Ast.NumberExpression(2))}
        )
    }, rleInnerScope)
    local rleElseBody = Ast.Block({appendByte(Ast.VariableExpression(rleScope, rleByte))}, ifScope2)

    local rleIfStmt = Ast.IfStatement(
        Ast.EqualsExpression(
            Ast.VariableExpression(rleScope, rleByte),
            Ast.NumberExpression(255)
        ),
        rleIfBody, {}, rleElseBody
    )

    local rleLoopBody = Ast.Block({
        Ast.LocalVariableDeclaration(rleScope, {rleByte}, {
            Ast.FunctionCallExpression(Ast.VariableExpression(rootScope, vSB), {
                Ast.VariableExpression(rootScope, vPacked),
                Ast.VariableExpression(rleScope, rleI)
            })
        }),
        rleIfStmt
    }, rleScope)

    local rleDecodeLoop = Ast.ForStatement(
        rleScope, rleI,
        Ast.NumberExpression(1),
        Ast.LenExpression(Ast.VariableExpression(rootScope, vPacked)),
        Ast.NumberExpression(1),
        rleLoopBody, rootScope
    )

    local stmts = {
        Ast.LocalVariableDeclaration(rootScope, {vSB},     {Ast.IndexExpression(Ast.VariableExpression(rootScope:resolveGlobal("string")), Ast.StringExpression("byte"))}),
        Ast.LocalVariableDeclaration(rootScope, {vPacked}, {Ast.StringExpression(packedStr)}),
        Ast.LocalVariableDeclaration(rootScope, {vKey},    {Ast.NumberExpression(xorKey)}),
        Ast.LocalVariableDeclaration(rootScope, {vIds},    {Ast.TableConstructorExpression({})}),
        Ast.LocalVariableDeclaration(rootScope, {vRaw},    {Ast.TableConstructorExpression({})}),
        rleDecodeLoop,
        forLoop,
    }
    for i, s in ipairs(stmts) do
        table.insert(ast.body.statements, i, s)
    end

    -- Substitui cada block ID por _ids[index]
    for _, t in ipairs(targets) do
        local idx = idIndex[t.id]
        if idx then
            t.rhs.kind  = AstKind.IndexExpression
            t.rhs.base  = Ast.VariableExpression(rootScope, vIds)
            t.rhs.index = Ast.NumberExpression(idx)
            t.rhs.value = nil; t.rhs.args = nil
        end
    end
    return ast
end

return PackBytecode;
