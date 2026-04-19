#!/bin/bash

echo "🧪 Testando Bot de Discord Localmente"
echo ""

# Verificar Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js não encontrado!"
    echo "   Instale em: https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js: $(node --version)"

# Verificar Lua
if ! command -v lua &> /dev/null; then
    echo "❌ Lua não encontrado!"
    echo "   Instale Lua 5.1+"
    exit 1
fi

echo "✅ Lua: $(lua -v)"
echo ""

# Verificar .env
if [ ! -f ".env" ]; then
    echo "⚠️  Arquivo .env não encontrado!"
    echo "   Crie um arquivo .env com:"
    echo "   DISCORD_TOKEN=seu_token_aqui"
    echo ""
    read -p "Deseja criar .env agora? (s/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        read -p "Cole seu token do Discord: " token
        echo "DISCORD_TOKEN=$token" > .env
        echo "✅ Arquivo .env criado!"
    else
        exit 1
    fi
fi

# Verificar node_modules
if [ ! -d "node_modules" ]; then
    echo "📦 Instalando dependências..."
    npm install
fi

echo ""
echo "🚀 Iniciando bot..."
echo "   Pressione Ctrl+C para parar"
echo ""

npm start
