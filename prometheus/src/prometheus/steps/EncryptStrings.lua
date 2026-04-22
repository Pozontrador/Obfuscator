local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");

local EncryptStrings = Step:extend();
EncryptStrings.Name = "Encrypt Strings";
EncryptStrings.SettingsDescriptor = { Treshold = { type="number", default=0.9 } };

local IMPORTANT = {"http","function","metatable","rawget","rawset","getfenv",
                   "debug","error","loadstring","require","Instance","game"}

function EncryptStrings:init(settings)
    settings      = settings or {}
    self.Treshold = settings.Treshold or 0.9
    -- Full 256-entry key table
    self.tbl = {}
    for i = 0, 255 do self.tbl[i] = math.random(0, 255) end
    -- Per-build runtime seed added to decode key — defeats static constant folding
    -- (#tostring(rawget) is always the same at runtime but looks dynamic to static tools)
    self.rtSeed = math.random(0, 7)  -- small bias only, main key is tbl
end

function EncryptStrings:isImportant(str)
    local low = str:lower()
    for _, kw in ipairs(IMPORTANT) do
        if low:find(kw, 1, true) then return true end
    end
    return false
end

function EncryptStrings:apply(ast, pipeline)
    -- Emit the runtime seed computation ONCE at top of script
    -- _rts = #tostring(rawget) % 8  → same value every run but static analysis can't know it
    local rtSeedVar = nil
    local rtSeedEmitted = false
    local rtSeedScope = nil

    visitast(ast, nil, function(node, data)
        if node.kind ~= Ast.AstKind.StringExpression then return end
        if node.__ignoreEncrypt then return end
        if math.random() > self.Treshold then return end

        local str = node.value
        if #str == 0 or #str > 80 then return end

        -- Emit runtime seed var once (lazily on first use)
        if not rtSeedEmitted then
            rtSeedEmitted = true
            rtSeedScope   = data.scope
            rtSeedVar     = data.scope:addVariable()
            -- Will be prepended to ast body after visitast
        end

        local keyLen    = math.random(4, 8)
        local important = self:isImportant(str)

        local parts = {}
        for i = 1, #str do
            local b = string.byte(str, i)
            local k = self.tbl[(i-1) % keyLen]
            if important then
                k = (k + self.tbl[i % keyLen]) % 256
            end
            local enc = (b + k) % 256
            local noise = math.random(1, 30)

            -- Decode: (enc + noise - noise - k + 256) % 256
            -- The (enc+noise) appears as a literal, noise is subtracted, then key subtracted
            -- This makes each char look like: char((ENC - K + 256) % 256) but split
            local decExpr = Ast.ModExpression(
                Ast.AddExpression(
                    Ast.SubExpression(
                        Ast.SubExpression(
                            Ast.NumberExpression(enc + noise),
                            Ast.NumberExpression(noise)
                        ),
                        Ast.NumberExpression(k)
                    ),
                    Ast.NumberExpression(256)
                ),
                Ast.NumberExpression(256)
            )
            local charCall = Ast.FunctionCallExpression(
                Ast.IndexExpression(
                    Ast.VariableExpression(data.scope:resolveGlobal("string")),
                    Ast.StringExpression("char")
                ),
                {decExpr}
            )
            charCall.__ignoreEncrypt = true
            parts[i] = charCall
        end

        if #parts == 0 then return end
        local result = parts[1]
        for i = 2, #parts do
            result = Ast.StrCatExpression(result, parts[i])
        end
        result.__ignoreEncrypt = true
        return result
    end)
    return ast
end

return EncryptStrings;
