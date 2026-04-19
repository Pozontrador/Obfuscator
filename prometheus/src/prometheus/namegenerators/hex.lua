-- Gerador de nomes que mistura estilos para evitar fingerprinting
local counter = 0
local seed    = 0
local style   = 0   -- 0=hex, 1=underscore+num, 2=double_underscore

local function generateName(id, scope)
    counter = counter + 1
    local n = (counter * 1664525 + seed) % 16777216
    -- Alterna estilo a cada bloco de 7 variáveis
    local s = math.floor(counter / 7) % 3
    if s == 0 then
        return string.format("_0x%05x", n)
    elseif s == 1 then
        return string.format("_%d_%d", seed % 999, counter)
    else
        return string.format("__%x%x", n % 4096, (n * 31) % 4096)
    end
end

local function prepare(ast)
    counter = 0
    seed    = math.random(0x1000, 0xFFFF)
    style   = math.random(0, 2)
end

return {
    generateName = generateName,
    prepare      = prepare
}
