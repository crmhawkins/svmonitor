const { exec, spawn } = require('child_process');
const io = require('socket.io-client');
const os = require('os');
const config = require('../config');

// Detectar sistema operativo
const isWindows = process.platform === 'win32';
const isLinux = process.platform === 'linux';

// URL del dashboard - siempre localhost interno
const DASHBOARD_PORT = process.env.DASHBOARD_PORT || config.dashboardPort;
const CENTRAL_URL = config.getDashboardUrl();

console.log(`🛰️ Agente Sentinel iniciando...`);
console.log(`📡 Conectando a: ${CENTRAL_URL}`);
console.log(`💻 Sistema: ${process.platform}`);

// Configurar socket con reconexión automática
const socket = io(CENTRAL_URL, {
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionAttempts: Infinity,
    timeout: 20000
});

let healthInterval = null;
let networkInterval = null;
let fileWatcher = null;

// Manejo de conexión
socket.on('connect', () => {
    console.log('✅ Conectado al dashboard');
    startMonitoring();
});

socket.on('disconnect', () => {
    console.log('❌ Desconectado del dashboard. Reintentando...');
    stopMonitoring();
});

socket.on('connect_error', (error) => {
    console.error('❌ Error de conexión:', error.message);
    console.log('💡 Asegúrate de que el dashboard esté ejecutándose');
});

socket.on('error', (error) => {
    console.error('❌ Error en socket:', error);
});

// Iniciar monitoreo
function startMonitoring() {
    // Estadísticas de salud del sistema
    healthInterval = setInterval(() => {
        try {
            let cpuLoad = 0;
            
            if (isWindows) {
                // Windows no tiene loadavg, usar alternativa
                cpuLoad = (process.cpuUsage().user + process.cpuUsage().system) / 1000000;
            } else {
                cpuLoad = os.loadavg()[0] || 0;
            }
            
            const memUsage = ((1 - os.freemem() / os.totalmem()) * 100).toFixed(2);
            
            socket.emit('health_stats', {
                cpu: cpuLoad.toFixed(2),
                mem: memUsage,
                ts: Date.now()
            });
        } catch (error) {
            console.error('❌ Error al obtener estadísticas:', error);
        }
    }, config.healthCheckInterval);

    // Alertas de red (compatible Windows/Linux)
    networkInterval = setInterval(() => {
        try {
            if (isWindows) {
                // Windows: usar netstat
                exec('netstat -an | findstr "ESTABLISHED SYN_SENT"', { timeout: 1000 }, (err, stdout) => {
                    if (!err && stdout) {
                        const suspicious = stdout.split('\n').filter(line => 
                            line.includes('php') || line.includes('SYN_SENT')
                        ).join('\n');
                        if (suspicious) {
                            socket.emit('network_alert', suspicious);
                        }
                    }
                });
            } else {
                // Linux: usar ss o netstat
                exec("ss -atpun 2>/dev/null | grep -E 'php|SYN_SENT' || netstat -tulpn 2>/dev/null | grep -E 'php|SYN_SENT'", 
                    { timeout: 1000 }, 
                    (err, stdout) => {
                        if (!err && stdout) {
                            socket.emit('network_alert', stdout);
                        }
                    }
                );
            }
        } catch (error) {
            console.error('❌ Error al verificar red:', error);
        }
    }, config.networkCheckInterval);

    // Monitor de archivos (solo Linux con inotify)
    if (isLinux) {
        try {
            const watchPath = process.env.WATCH_PATH || '/var/www/vhosts';
            fileWatcher = spawn('inotifywait', ['-mr', '-e', 'modify,create,delete', watchPath], {
                stdio: ['ignore', 'pipe', 'pipe']
            });
            
            fileWatcher.stdout.on('data', (data) => {
                socket.emit('file_change', { 
                    detail: data.toString().trim(), 
                    ts: Date.now() 
                });
            });
            
            fileWatcher.stderr.on('data', (data) => {
                // Ignorar errores menores de inotifywait
                if (!data.toString().includes('Couldn\'t watch')) {
                    console.warn('⚠️ inotifywait:', data.toString().trim());
                }
            });
            
            fileWatcher.on('error', (error) => {
                console.warn('⚠️ inotifywait no disponible:', error.message);
                console.log('💡 El monitoreo de archivos está deshabilitado');
            });
        } catch (error) {
            console.warn('⚠️ No se pudo iniciar el monitor de archivos:', error.message);
        }
    } else {
        console.log('💡 Monitor de archivos disponible solo en Linux');
    }
}

// Detener monitoreo
function stopMonitoring() {
    if (healthInterval) {
        clearInterval(healthInterval);
        healthInterval = null;
    }
    if (networkInterval) {
        clearInterval(networkInterval);
        networkInterval = null;
    }
    if (fileWatcher) {
        fileWatcher.kill();
        fileWatcher = null;
    }
}

// Protocolo de Pánico (solo Linux)
socket.on('trigger_panic', () => {
    console.warn('🚨 PROTOCOLO DE PÁNICO ACTIVADO');
    
    if (isLinux) {
        exec("iptables -P OUTPUT DROP && iptables -I OUTPUT -p tcp --dport 22 -j ACCEPT && iptables -I OUTPUT -o lo -j ACCEPT", 
            (error, stdout, stderr) => {
                if (error) {
                    console.error('❌ Error al ejecutar protocolo de pánico:', error);
                } else {
                    console.log('✅ Protocolo de pánico ejecutado');
                }
            }
        );
    } else {
        console.warn('⚠️ Protocolo de pánico solo disponible en Linux');
    }
});

// Limpieza al cerrar
process.on('SIGINT', () => {
    console.log('\n🛑 Deteniendo agente...');
    stopMonitoring();
    socket.disconnect();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n🛑 Deteniendo agente...');
    stopMonitoring();
    socket.disconnect();
    process.exit(0);
});

// Manejo de errores no capturados
process.on('uncaughtException', (err) => {
    console.error('❌ Error no capturado:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Promesa rechazada no manejada:', reason);
});
