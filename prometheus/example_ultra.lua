-- Example: How to use the Ultra preset

-- Load Prometheus
local Prometheus = require("prometheus");

-- Example input code to obfuscate
local inputCode = [[
local function greet(name)
    print("Hello, " .. name .. "!")
    return true
end

local function calculate(a, b)
    local sum = a + b
    local product = a * b
    return sum, product
end

greet("World")
local s, p = calculate(5, 10)
print("Sum: " .. s .. ", Product: " .. p)
]]

-- Load the Ultra preset
local config = Prometheus.Presets.Ultra;

print("=== Prometheus Obfuscator - Ultra Preset Example ===")
print()
print("Input Code Length: " .. #inputCode .. " bytes")
print()

-- Create pipeline from config
local pipeline = Prometheus.Pipeline:fromConfig(config);

-- Apply obfuscation
print("Applying obfuscation...")
print("Steps:")
for i, step in ipairs(config.Steps) do
    print("  " .. i .. ". " .. step.Name)
end
print()

local outputCode = pipeline:apply(inputCode);

print("Output Code Length: " .. #outputCode .. " bytes")
print("Obfuscation complete!")
print()
print("--- Obfuscated Code ---")
print(outputCode)
print("--- End ---")

-- You can also save to file:
local file = io.open("obfuscated_output.lua", "w")
if file then
    file:write(outputCode)
    file:close()
    print()
    print("Saved to: obfuscated_output.lua")
end
