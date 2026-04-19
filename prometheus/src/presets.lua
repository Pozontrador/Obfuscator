return {
    ["Ultra"] = {
        LuaVersion = "Lua51";
        VarNamePrefix = "IlIlIl_";
        NameGenerator = "MangledShuffled";
        PrettyPrint = false;
        Seed = math.random(1e9);
        
        Steps = {
            -- ProxifyLocals foi REMOVIDO pois é incompatível com métodos de jogos (causador do erro de 'sub on function')

            -- 1. Picota as funções para confundir a análise estática
            { Name = "AddVararg", Settings = {} },

            -- 2. Transforma strings curtas em cálculos de bytes
            { Name = "AdvancedStrings", Settings = { Treshold = 0.5 } }, 
            
            -- 3. Criptografa o restante
            { Name = "EncryptStrings", Settings = {} },
            
            -- 4. Pega as strings longas criptografadas e divide em tabelas
            { Name = "SplitStrings", Settings = { Treshold = 0.5, MinLength = 10, MaxLength = 20, ConcatenationType = "table" } },
            
            -- 5. Muta os números com matemática leve (Low Overhead)
            { Name = "NumbersToExpressions", Settings = { Treshold = 0.3 } },
            
            -- 6. Achata o fluxo lógico (Otimizado para não dar Script Exhausted)
            { Name = "ControlFlowFlattening", Settings = { Treshold = 0.3, MinStatements = 5 } },
            
            -- 7. Engole o seu script e cria uma linguagem alienígena
            { Name = "Vmify", Settings = {} },
            
            -- 8. Isola os números e strings da VM em um cofre
            { Name = "ConstantArray", Settings = { Treshold = 1, StringsOnly = false, Shuffle = true, Rotate = true } },
            
            -- 9. Protege contra ferramentas de Dump
            { Name = "AntiTamper", Settings = { UseDebug = false } },
            
            -- 10. Esconde o escopo global
            { Name = "WrapInFunction", Settings = { Iterations = 1 } },
        }
    },
}
