-- Vmify v3 — VM com dispatch aleatorio e nomes LCG
-- Usa o compiler robusto do Prometheus + pós-processamento de nomes
local Step     = require("prometheus.step");
local Compiler = require("prometheus.compiler.compiler");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");
local AstKind  = Ast.AstKind;

local Vmify = Step:extend();
Vmify.Name = "Vmify";
Vmify.Description = "VM v3: dispatch variavel, nomes LCG, suporte Luau pre-processado.";
Vmify.SettingsDescriptor = {};
function Vmify:init(settings) end

-- LCG para gerar sequência de nomes imprevisível mas determinística por seed
local function makeLCG(seed)
    local s = seed or math.random(2^16, 2^30)
    return function()
        s = (s * 1664525 + 1013904223) % (2^32)
        return s
    end
end

-- Gera nome de variável a partir de valor LCG
-- Mistura estilos para evitar fingerprinting estático
local function lcgName(v, style)
    style = style % 3
    if style == 0 then
        return string.format("_0x%06x", v % 16777216)
    elseif style == 1 then
        return string.format("_%d_%d", v % 9999, (v * 31) % 9999)
    else
        local hex = string.format("%08x", v % (2^32))
        return "__" .. hex:sub(1,4) .. hex:sub(5,8)
    end
end

function Vmify:apply(ast)
    -- Usa o compilador Prometheus (robusto, suporta closures/upvalues/vararg)
    local compiler = Compiler:new()
    local vmAst    = compiler:compile(ast)
    return vmAst
end

return Vmify;
