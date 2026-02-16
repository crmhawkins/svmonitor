# --- CONFIGURACIÓN DE RUTA LOCAL ---
$RUTA_PROYECTO = "./"

Write-Host "🚀 Creando estructura de Sentinel en $RUTA_PROYECTO..." -ForegroundColor Cyan

# 1. Crear carpetas
New-Item -ItemType Directory -Force -Path "$RUTA_PROYECTO\agent"
New-Item -ItemType Directory -Force -Path "$RUTA_PROYECTO\dashboard"

# 2. Crear el Agente (agent.js)
$agentCode = @"
const { exec, spawn } = require('child_process');
const io = require('socket.io-client');
const os = require('os');

const CENTRAL_URL = 'http://localhost:4000'; // IP del dashboard
const socket = io(CENTRAL_URL);

console.log("🛰️ Agente Sentinel Activo");

// Estadísticas de salud
setInterval(() => {
    socket.emit('health_stats', {
        cpu: (os.loadavg()[0]).toFixed(2),
        mem: ((1 - os.freemem() / os.totalmem()) * 100).toFixed(2),
        ts: Date.now()
    });
}, 3000);

// Alertas de red (PHP y conexiones sospechosas)
setInterval(() => {
    exec("ss -atpun | grep 'php\\\\|SYN_SENT'", (err, stdout) => {
        if (stdout) socket.emit('network_alert', stdout);
    });
}, 2000);

// Monitor de archivos en tiempo real
const watcher = spawn('inotifywait', ['-mr', '-e', 'modify,create,delete', '/var/www/vhosts']);
watcher.stdout.on('data', (data) => {
    socket.emit('file_change', { detail: data.toString().trim(), ts: Date.now() });
});

// Protocolo de Pánico
socket.on('trigger_panic', () => {
    exec("iptables -P OUTPUT DROP && iptables -I OUTPUT -p tcp --dport 22 -j ACCEPT && iptables -I OUTPUT -o lo -j ACCEPT");
});
"@
$agentCode | Out-File -FilePath "$RUTA_PROYECTO\agent\agent.js" -Encoding utf8

# 3. Crear el Servidor (server.js)
$serverCode = @"
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

io.on('connection', (socket) => {
    socket.on('health_stats', (data) => io.emit('ui_health', data));
    socket.on('network_alert', (data) => io.emit('ui_network', data));
    socket.on('file_change', (data) => io.emit('ui_file', data));
    socket.on('panic_action', () => io.emit('trigger_panic'));
});

server.listen(4000, '0.0.0.0', () => console.log('✅ Dashboard en puerto 4000'));
"@
$serverCode | Out-File -FilePath "$RUTA_PROYECTO\dashboard\server.js" -Encoding utf8

# 4. Crear el Interfaz (index.html)
$htmlCode = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>SENTINEL HUB</title>
    <script src="/socket.io/socket.io.js"></script>
    <style>
        body { background: #0d1117; color: #c9d1d9; font-family: sans-serif; padding: 20px; }
        .card { background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 8px; text-align: center; }
        .panic { background: #da3633; color: white; border: none; padding: 20px; width: 100%; border-radius: 8px; font-weight: bold; cursor: pointer; margin-top: 20px; }
        .console { background: #000; color: #39ff14; padding: 15px; height: 300px; overflow-y: auto; font-family: monospace; border-radius: 6px; text-align: left; }
        .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
        .stats { font-size: 2rem; color: #58a6ff; }
    </style>
</head>
<body>
    <h1>🛰️ SISTEMA SENTINEL</h1>
    <div class="grid">
        <div class="card">CPU <div id="cpu" class="stats">0%</div></div>
        <div class="card">MEM <div id="mem" class="stats">0%</div></div>
        <div class="card">AMENAZA <div id="threat" class="stats" style="color:#ffa657">BAJA</div></div>
    </div>
    <button class="panic" onclick="if(confirm('¿BLOQUEAR TODO?')) socket.emit('panic_action')">🚨 PROTOCOLO DE PÁNICO</button>
    <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
        <div><h3>🌐 RED</h3><pre id="net" class="console"></pre></div>
        <div><h3>📂 ARCHIVOS</h3><pre id="file" class="console"></pre></div>
    </div>
    <script>
        const socket = io();
        socket.on('ui_health', d => { document.getElementById('cpu').innerText = d.cpu+'%'; document.getElementById('mem').innerText = d.mem+'%'; });
        socket.on('ui_network', d => { 
            document.getElementById('net').innerText = d;
            document.getElementById('threat').innerText = d.includes('SYN_SENT') ? 'CRÍTICA' : 'BAJA';
            document.getElementById('threat').style.color = d.includes('SYN_SENT') ? '#da3633' : '#ffa657';
        });
        socket.on('ui_file', d => { document.getElementById('file').innerHTML = '['+new Date(d.ts).toLocaleTimeString()+'] '+d.detail+'\n' + document.getElementById('file').innerHTML; });
    </script>
</body>
</html>
"@
$htmlCode | Out-File -FilePath "$RUTA_PROYECTO\dashboard\index.html" -Encoding utf8

Write-Host "✅ Archivos creados en tu Escritorio dentro de la carpeta 'Sentinel-Pro'" -ForegroundColor Green