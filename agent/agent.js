const { exec, spawn } = require('child_process');
const io = require('socket.io-client');
const os = require('os');

const CENTRAL_URL = 'http://localhost:4000'; // IP del dashboard
const socket = io(CENTRAL_URL);

console.log("ðŸ›°ï¸ Agente Sentinel Activo");

// EstadÃ­sticas de salud
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

// Protocolo de PÃ¡nico
socket.on('trigger_panic', () => {
    exec("iptables -P OUTPUT DROP && iptables -I OUTPUT -p tcp --dport 22 -j ACCEPT && iptables -I OUTPUT -o lo -j ACCEPT");
});
