local Step     = require("prometheus.step");
local Ast      = require("prometheus.ast");
local visitast = require("prometheus.visitast");

local NumbersToExpressions = Step:extend();
NumbersToExpressions.Name = "Numbers To Expressions";
NumbersToExpressions.SettingsDescriptor = {
    Treshold = { type="number", default=0.6 }
};
function NumbersToExpressions:init(settings)
    settings = settings or {}
    self.Treshold = settings.Treshold or 0.6
end

local function buildExpr(val)
    local s = math.random(1, 9)

    if s == 1 then
        -- ((val + a) * b - a*b) / b
        local a = math.random(5, 50)
        local b = math.random(2, 9)
        -- ((val + a) * b - a*b) / b = (val*b + a*b - a*b)/b = val
        local e = Ast.DivExpression(
            Ast.SubExpression(
                Ast.MulExpression(
                    Ast.AddExpression(Ast.NumberExpression(val), Ast.NumberExpression(a)),
                    Ast.NumberExpression(b)
                ),
                Ast.NumberExpression(a * b)
            ),
            Ast.NumberExpression(b)
        )
        e.__ignoreNum = true
        return e

    elseif s == 2 then
        -- (val + a + b) - (a + b)
        local a = math.random(10, 200)
        local b = math.random(10, 200)
        local e = Ast.SubExpression(
            Ast.NumberExpression(val + a + b),
            Ast.AddExpression(Ast.NumberExpression(a), Ast.NumberExpression(b))
        )
        e.__ignoreNum = true
        return e

    elseif s == 3 then
        -- (val - a) + a   with a random
        local a = math.random(5, 150)
        local e = Ast.AddExpression(
            Ast.NumberExpression(val - a),
            Ast.NumberExpression(a)
        )
        e.__ignoreNum = true
        return e

    elseif s == 4 then
        -- val * a / a  (prime divisor)
        local primes = {7, 11, 13, 17, 19, 23, 29, 31}
        local p = primes[math.random(#primes)]
        if val ~= 0 then
            local e = Ast.DivExpression(
                Ast.MulExpression(Ast.NumberExpression(val * p), Ast.NumberExpression(1)),
                Ast.NumberExpression(p)
            )
            e.__ignoreNum = true
            return e
        end

    elseif s == 5 then
        -- (val + k) - k  nested twice
        local k1 = math.random(50, 300)
        local k2 = math.random(50, 300)
        local e = Ast.SubExpression(
            Ast.AddExpression(
                Ast.SubExpression(Ast.NumberExpression(val + k1 + k2), Ast.NumberExpression(k1)),
                Ast.NumberExpression(k1)
            ),
            Ast.NumberExpression(k1 + k2)
        )
        e.__ignoreNum = true
        return e

    elseif s == 6 then
        -- val + (k - k)
        local k = math.random(100, 9999)
        local e = Ast.AddExpression(
            Ast.NumberExpression(val),
            Ast.SubExpression(Ast.NumberExpression(k), Ast.NumberExpression(k))
        )
        e.__ignoreNum = true
        return e

    elseif s == 7 then
        -- val * (a/a) where a != 0
        if val ~= 0 then
            local a = math.random(2, 20)
            local e = Ast.MulExpression(
                Ast.NumberExpression(val),
                Ast.DivExpression(Ast.NumberExpression(a), Ast.NumberExpression(a))
            )
            e.__ignoreNum = true
            return e
        end

    elseif s == 8 then
        -- (val*2 + k) / 2 - k/2  (only for even k)
        local k = math.random(1, 50) * 2  -- always even
        local e = Ast.SubExpression(
            Ast.DivExpression(
                Ast.AddExpression(
                    Ast.MulExpression(Ast.NumberExpression(val), Ast.NumberExpression(2)),
                    Ast.NumberExpression(k)
                ),
                Ast.NumberExpression(2)
            ),
            Ast.NumberExpression(k / 2)
        )
        e.__ignoreNum = true
        return e
    else
        -- Scientific notation: val = mantissa * 10^exp
        -- Only for values that have a clean scientific form
        -- e.g. 1000 = 1e3, 250 = 2.5e2
        -- We emit: val + 0 (with val as scientific literal via string trick)
        -- Prometheus NumberExpression takes a number value - it will print as scientific if appropriate
        -- Force scientific: emit val*1.0 to trigger float printing
        if val ~= 0 and math.abs(val) >= 100 then
            local exp = math.floor(math.log(math.abs(val)) / math.log(10))
            local mantissa = val / (10 ^ exp)
            -- mantissa * 10^exp = val
            -- emit as: mantissa * 10^exp
            local e = Ast.MulExpression(
                Ast.NumberExpression(mantissa),
                Ast.NumberExpression(10 ^ exp)
            )
            e.__ignoreNum = true
            return e
        end
        local k = math.random(1, 300)
        local e = Ast.AddExpression(Ast.NumberExpression(val - k), Ast.NumberExpression(k))
        e.__ignoreNum = true
        return e
    end
end

function NumbersToExpressions:apply(ast)
    visitast(ast, nil, function(node, data)
        if node.kind == Ast.AstKind.NumberExpression and not node.__ignoreNum then
            if math.random() <= self.Treshold then
                local v = node.value
                if type(v) == "number" and v == math.floor(v)
                and v >= -50000 and v <= 50000 then
                    local expr = buildExpr(v)
                    if expr then return expr end
                end
            end
        end
    end)
    return ast
end

return NumbersToExpressions;
