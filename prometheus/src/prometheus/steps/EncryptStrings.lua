local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");

local EncryptStrings = Step:extend();
EncryptStrings.Name = "Encrypt Strings";
EncryptStrings.SettingsDescriptor = { Treshold = { type="number", default=0.9 } };

local IMPORTANT = {"http","function","metatable","rawget","rawset","getfenv","debug","error","loadstring","require"}

function EncryptStrings:init(settings)
    settings      = settings or {}
    self.Treshold = settings.Treshold or 0.9
    -- 256-entry lookup table (IronBrew style)
    self.tbl = {}
    for i = 0, 255 do self.tbl[i] = math.random(0, 127) end
end

function EncryptStrings:isImportant(str)
    local low = str:lower()
    for _, kw in ipairs(IMPORTANT) do
        if low:find(kw, 1, true) then return true end
    end
    return false
end

function EncryptStrings:apply(ast, pipeline)
    visitast(ast, nil, function(node, data)
        if node.kind ~= Ast.AstKind.StringExpression then return end
        if node.__ignoreEncrypt then return end
        if math.random() > self.Treshold then return end

        local str = node.value
        if #str == 0 or #str > 60 then return end

        -- Per-string key length (4-8 bytes from the 256-table)
        local keyLen = math.random(4, 8)
        local important = self:isImportant(str)

        local parts = {}
        for i = 1, #str do
            local b   = string.byte(str, i)
            local k   = self.tbl[(i-1) % keyLen]
            -- Important strings: double XOR
            if important then
                k = (k + self.tbl[(i) % keyLen]) % 128
            end
            local enc = (b + k) % 256
            local noise = math.random(1, 50)
            -- Decode: (enc - k + 256) % 256
            local decExpr = Ast.ModExpression(
                Ast.AddExpression(
                    Ast.SubExpression(
                        Ast.SubExpression(Ast.NumberExpression(enc + noise), Ast.NumberExpression(noise)),
                        Ast.NumberExpression(k)
                    ),
                    Ast.NumberExpression(256)
                ),
                Ast.NumberExpression(256)
            )
            local charRef = Ast.IndexExpression(
                Ast.VariableExpression(data.scope:resolveGlobal("string")),
                Ast.StringExpression("char")
            )
            local call = Ast.FunctionCallExpression(charRef, {decExpr})
            call.__ignoreEncrypt = true
            parts[i] = call
        end

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
