require('dotenv').config();
const { Client, GatewayIntentBits, Partials, EmbedBuilder, AttachmentBuilder } = require('discord.js');
const { exec } = require('child_process');
const { promisify } = require('util');
const fs    = require('fs').promises;
const path  = require('path');
const https = require('https');
const http  = require('http');
const execAsync = promisify(exec);

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages,
    ],
    partials: [Partials.Channel, Partials.Message],
});

const PREFIX   = '.';
const TEMP_DIR = '/tmp/obfuscator';

let totalObfuscated = 0;
const STATS_FILE = path.join(TEMP_DIR, 'stats.json');

async function loadStats() {
    try { totalObfuscated = JSON.parse(await fs.readFile(STATS_FILE, 'utf8')).total || 0; } catch {}
}
async function saveStats() {
    try { await fs.writeFile(STATS_FILE, JSON.stringify({ total: totalObfuscated }), 'utf8'); } catch {}
}
async function ensureTempDir() {
    try { await fs.mkdir(TEMP_DIR, { recursive: true }); await loadStats(); } catch {}
}
async function cleanup(...files) {
    for (const f of files) try { await fs.unlink(f); } catch {}
}

// ── File download ─────────────────────────────────────────────────────────────
function downloadFile(url, hops) {
    hops = hops || 0;
    if (hops > 5) return Promise.reject(new Error('Too many redirects'));
    return new Promise((resolve, reject) => {
        const lib = url.startsWith('https') ? https : http;
        lib.get(url, { headers: { 'User-Agent': 'AlphaxBot/1.0' } }, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                const next = res.headers.location.startsWith('http')
                    ? res.headers.location
                    : new URL(res.headers.location, url).href;
                res.resume();
                return downloadFile(next, hops + 1).then(resolve).catch(reject);
            }
            if (res.statusCode !== 200) {
                res.resume();
                return reject(new Error(`HTTP ${res.statusCode}`));
            }
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end',  () => resolve(Buffer.concat(chunks).toString('utf8')));
            res.on('error', reject);
        }).on('error', reject);
    });
}

// ── Obfuscation ───────────────────────────────────────────────────────────────
async function obfuscateCode(code) {
    const ts  = Date.now();
    const inp = path.join(TEMP_DIR, `i_${ts}.lua`);
    const out = path.join(TEMP_DIR, `o_${ts}.lua`);
    const cfg = path.join(TEMP_DIR, `c_${ts}.lua`);

    try {
        await fs.writeFile(inp, code, 'utf8');

        const pp = process.env.RAILWAY_ENVIRONMENT
            ? '/app/prometheus/src'
            : path.join(__dirname, 'prometheus', 'src');

        const ppFwd  = pp.replace(/\\/g, '/');
        const inpFwd = inp.replace(/\\/g, '/');
        const outFwd = out.replace(/\\/g, '/');

                // Dynamic pipeline: skip heavy steps for large/Roblox scripts
        const scriptSize = code.length;
        const hasRobloxGlobals = /\b(task\.wait|task\.spawn|Instance\.new|UDim2|Color3|TweenService|Players\.|game:GetService|workspace\.|script\.)/.test(code);
        const isLarge = scriptSize > 8000;

        let stepsCode;
        if (isLarge || hasRobloxGlobals) {
            // Lightweight pipeline for large/Roblox scripts — no Vmify, no EncryptStrings
            stepsCode = `
            { Name = "AddVararg",             Settings = {} },
            { Name = "ConstantArray",         Settings = { Treshold = 0.8, StringsOnly = false, Shuffle = true } },
            { Name = "NumbersToExpressions",  Settings = { Treshold = 0.2 } },
            { Name = "SplitStrings",          Settings = { Treshold = 0.5, MinLength = 4, MaxLength = 8 } },
            { Name = "OpaquePredicates",      Settings = { Treshold = 0.1 } },
            { Name = "AntiTamper",            Settings = {} },
            { Name = "WrapInFunction",        Settings = { Iterations = 2 } }
        `;
        } else {
            // Full pipeline for small pure Lua scripts
            stepsCode = `
            { Name = "AddVararg",             Settings = {} },
            { Name = "Vmify",                 Settings = {} },
            { Name = "PackBytecode",          Settings = {} },
            { Name = "ConstantArray",         Settings = { Treshold = 1, StringsOnly = false, Shuffle = true } },
            { Name = "EncryptStrings",        Settings = { Treshold = 1 } },
            { Name = "ControlFlowFlattening", Settings = { Treshold = 0.25, MinStatements = 3, MaxStatements = 8 } },
            { Name = "NumbersToExpressions",  Settings = { Treshold = 0.5 } },
            { Name = "SplitStrings",          Settings = { Treshold = 0.8, MinLength = 2, MaxLength = 8 } },
            { Name = "OpaquePredicates",      Settings = { Treshold = 0.2 } },
            { Name = "AntiTamper",            Settings = {} },
            { Name = "WrapInFunction",        Settings = { Iterations = 2 } }
        `;
        }

        const luaScript = [
            'unpack = unpack or table.unpack',
            'loadstring = loadstring or load',
            'table.unpack = table.unpack or unpack',
            '',
            `local pp = "${ppFwd}"`,
            'package.path = package.path .. ";" .. pp .. "/?.lua"',
            '',
            'local _tf = io.open(pp .. "/prometheus.lua","r")',
            'if not _tf then print("FATAL_ERROR: prometheus not found") os.exit(1) end',
            '_tf:close()',
            '',
            'local ok,P = pcall(require,"prometheus")',
            'if not ok then print("FATAL_ERROR:"..tostring(P)) os.exit(1) end',
            '',
            `local f = io.open("${inpFwd}", "r")`,
            'if not f then print("FATAL_ERROR: cannot open input") os.exit(1) end',
            'local src = f:read("*all") f:close()',
            '',
            'local ok2,pipeline = pcall(function()',
            '    return P.Pipeline:fromConfig({',
            '        LuaVersion    = "Lua51",',
            '        VarNamePrefix = "",',
            '        NameGenerator = "Hex",',
            '        PrettyPrint   = false,',
            '        Seed          = math.random(1e9),',
            `        Steps         = { ${stepsCode} }`,
            '    })',
            'end)',
            'if not ok2 then print("FATAL_ERROR:"..tostring(pipeline)) os.exit(1) end',
            '',
            'local ok3,result = pcall(function() return pipeline:apply(src) end)',
            'if not ok3 then print("FATAL_ERROR:"..tostring(result)) os.exit(1) end',
            '',
            `local o = io.open("${outFwd}", "w")`,
            'if not o then print("FATAL_ERROR: cannot write output") os.exit(1) end',
            'o:write(result) o:close()',
            'print("SUCCESS")',
        ].join('\n');

        await fs.writeFile(cfg, luaScript, 'utf8');

        let stdout = '', stderr = '';
        try {
            const r = await execAsync(`lua5.1 "${cfg}"`, {
                timeout: 270000,
                cwd: TEMP_DIR,
                maxBuffer: 50 * 1024 * 1024,
                killSignal: 'SIGKILL',
            });
            stdout = r.stdout;
            stderr = r.stderr;
        } catch (e) {
            stdout = e.stdout || '';
            stderr = e.stderr || e.message;
            if (e.killed || e.signal === 'SIGKILL') {
                await cleanup(inp, out, cfg);
                return { success: false, error: '⚠️ Script too large or complex. Process was killed.' };
            }
        }

        if (stdout.includes('FATAL_ERROR') || !stdout.includes('SUCCESS')) {
            await cleanup(inp, out, cfg);
            const log = (stdout || stderr).substring(0, 1200);

            // Detect Luau/syntax errors — show clean message in chat
            const isParseError = log.includes('Parsing Error') || log.includes('unexpected symbol')
                || log.includes('parsing') || log.includes('parse')
                || log.includes("'=' expected") || log.includes("'end' expected")
                || log.includes("'<eof>' expected") || log.includes("unfinished");

            if (isParseError) {
                return { success: false, error: '❌ **Syntax Error** — your script contains Luau syntax not supported in Lua 5.1.\n\n**Common causes:**\n> • `+=`, `-=`, `*=`, `//=` compound operators\n> • `continue` keyword\n> • Type annotations like `: string`, `: number`\n> • `task.wait()` or other Roblox-specific globals\n\nConvert your script to **pure Lua 5.1** and try again.' };
            }

            // FATAL or unknown error — DM owner silently, return generic message in chat
            try {
                const owner = await client.users.fetch('1168949298784895116');
                await owner.send({ embeds: [{ color: 0xff4444, title: '❌ FATAL Error', description: '```\n' + log.slice(0, 1800) + '\n```', timestamp: new Date().toISOString() }] });
            } catch {}
            return { success: false, error: '❌ **Obfuscation failed.** An internal error occurred. The developer has been notified.' };
        }

        const obfuscated = await fs.readFile(out, 'utf8');
        await cleanup(inp, out, cfg);
        return { success: true, code: '--[[ Alphax Obfuscator v1.0 BETA ]]\n' + obfuscated };

    } catch (e) {
        await cleanup(inp, out, cfg);
        return { success: false, error: e.message };
    }
}

// ── Discord events ─────────────────────────────────────────────────────────────
client.on('messageCreate', async (message) => {
    if (message.author.bot) return;
    if (!message.content.startsWith(PREFIX)) return;

    const args    = message.content.slice(PREFIX.length).trim().split(/ +/);
    const command = args.shift().toLowerCase();

    if (command !== 'obf' && command !== 'obfuscate') return;

    const attachment = message.attachments.first();

    // ── Detect inline code in message content ─────────────────────────────
    // Supports: .obf ```lua ... ``` or .obf `...`
    let code = null;
    const fullContent = message.content;
    const tripleMatch = fullContent.match(/```(?:lua)?\s*([\s\S]+?)```/);
    const singleMatch = fullContent.match(/`([^`]+)`/);

    if (tripleMatch) {
        code = tripleMatch[1].trim();
    } else if (singleMatch) {
        code = singleMatch[1].trim();
    }

    if (!code && !attachment) {
        return message.reply('❌ Attach a `.lua` file or paste code in backticks: `.obf ```lua ... ````');
    }

    if (!code && attachment) {
        if (!attachment.name.endsWith('.lua') && !attachment.name.endsWith('.txt')) {
            return message.reply('❌ Only `.lua` or `.txt` files are accepted.');
        }
        if (attachment.size > 10 * 1024 * 1024) {
            return message.reply('❌ File too large (max 10MB).');
        }
        try {
            const urls = [attachment.proxyURL, attachment.url].filter(Boolean);
            // Race both URLs in parallel — use whichever responds first
            code = await Promise.any(urls.map(url => downloadFile(url)))
                .catch(async () => {
                    // fallback sequential if Promise.any fails
                    for (const url of urls) {
                        try { const r = await downloadFile(url); if (r) return r; } catch {}
                    }
                    throw new Error('Download failed');
                });
            if (!code) throw new Error('Download failed');
        } catch (e) {
            return message.reply(`❌ Failed to download file: ${e.message}`);
        }
    }

    if (message.guild) try { await message.delete(); } catch {}

    const displayName = attachment ? attachment.name : 'inline code';
    const processing = await message.channel.send({
        content: `<@${message.author.id}> ⏳ Obfuscating **${displayName}**...`,
    });

    const result = await obfuscateCode(code);

    if (result.success) {
        totalObfuscated++;
        await saveStats();

        const buf  = Buffer.from(result.code, 'utf8');
        const ext  = attachment ? (attachment.name.endsWith('.lua') ? '.lua' : '.txt') : '.lua';
        const baseName = attachment ? attachment.name.replace(/\.(lua|txt)$/, '') : 'obfuscated';
        const name = baseName + `_obf${ext}`;

        if (buf.length > 50 * 1024 * 1024) {
            await processing.delete().catch(()=>{});
            try { await (await client.users.fetch("1168949298784895116")).send('❌ Output file too large for Discord (>50MB).'); } catch {}
            return;
        }

        const embed = new EmbedBuilder()
            .setColor('#00ff00')
            .setTitle('✅ Obfuscation complete!')
            .setDescription(
                `📄 **File:** ${displayName}\n` +
                `📦 **Size:** ${(buf.length / 1024).toFixed(1)} KB`
            )
            .setFooter({ text: 'Alphax Obfuscator v1.0 BETA' })
            .setTimestamp();

        await processing.edit({
            content: `<@${message.author.id}>`,
            embeds: [embed],
            files: [new AttachmentBuilder(buf, { name })],
        });

        client.user.setActivity(`.obf | ${totalObfuscated} scripts`, { type: 'WATCHING' });

    } else {
        await processing.delete().catch(() => {});
        try {
            await (await client.users.fetch("1168949298784895116")).send({
                embeds: [{
                    color: 0xff4444,
                    title: '❌ Obfuscation Failed',
                    description: `\`\`\`\n${result.error.slice(0, 1800)}\n\`\`\``,
                    footer: { text: 'Alphax Obfuscator v1.0 BETA' },
                    timestamp: new Date().toISOString()
                }]
            });
        } catch {}
    }
});

client.on('ready', () => {
    console.log(`✅ Online: ${client.user.tag}`);
    client.user.setActivity(`.obf | ${totalObfuscated} scripts`, { type: 'WATCHING' });
});

ensureTempDir().then(() => client.login(process.env.DISCORD_TOKEN));
