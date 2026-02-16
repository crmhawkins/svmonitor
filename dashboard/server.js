const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const config = require('../config');

const app = express();
const server = http.createServer(app);

// Configurar Socket.IO solo para localhost
const io = new Server(server, {
    cors: {
        origin: false,
        credentials: false
    },
    transports: ['websocket', 'polling']
});

// Servir archivos estáticos
app.use(express.static(path.join(__dirname)));

// Ruta principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Manejo de conexiones Socket.IO
io.on('connection', (socket) => {
    const clientIp = socket.handshake.address;
    console.log(`✅ Cliente conectado desde ${clientIp}`);
    
    // Validar que la conexión sea local (permitir también conexiones a través de nginx proxy)
    // Nginx puede enviar conexiones desde 127.0.0.1 cuando hace proxy
    const isLocal = clientIp.includes('127.0.0.1') || 
                    clientIp.includes('::1') || 
                    clientIp.includes('::ffff:127.0.0.1') ||
                    clientIp === '::ffff:127.0.0.1' ||
                    socket.handshake.headers['x-forwarded-for']?.includes('127.0.0.1');
    
    if (!isLocal) {
        console.warn(`⚠️ Intento de conexión desde IP externa: ${clientIp}`);
        socket.disconnect();
        return;
    }
    
    socket.on('health_stats', (data) => {
        if (data && typeof data === 'object') {
            io.emit('ui_health', data);
        }
    });
    
    socket.on('network_alert', (data) => {
        if (data) {
            io.emit('ui_network', data);
        }
    });
    
    socket.on('file_change', (data) => {
        if (data && typeof data === 'object') {
            io.emit('ui_file', data);
        }
    });
    
    socket.on('process_alert', (data) => {
        if (data && Array.isArray(data)) {
            io.emit('ui_process', data);
        }
    });
    
    socket.on('crontab_alert', (data) => {
        if (data && Array.isArray(data)) {
            io.emit('ui_crontab', data);
        }
    });
    
    socket.on('panic_action', () => {
        console.warn('🚨 PROTOCOLO DE PÁNICO ACTIVADO');
        io.emit('trigger_panic');
    });
    
    socket.on('disconnect', () => {
        console.log(`❌ Cliente desconectado: ${clientIp}`);
    });
    
    socket.on('error', (error) => {
        console.error('❌ Error en socket:', error);
    });
});

// Intentar iniciar en puerto 80, con fallback
function startServer() {
    const port = config.dashboardPort;
    const host = config.host;
    
    server.listen(port, host, () => {
        console.log(`✅ Dashboard activo en http://${host}:${port}`);
        if (port === 3813) {
            console.log(`🌐 Nginx debe redirigir el puerto 80 a este puerto interno`);
            console.log(`📋 Configura nginx para svmonitor.herasoft.ai -> http://127.0.0.1:${port}`);
        }
        console.log(`🔒 Comunicaciones restringidas a localhost únicamente`);
    }).on('error', (err) => {
        if (err.code === 'EACCES' || err.code === 'EADDRINUSE') {
            console.warn(`⚠️ No se pudo usar el puerto ${port}`);
            console.log(`🔄 Intentando puerto alternativo ${config.dashboardPortFallback}...`);
            
            server.listen(config.dashboardPortFallback, host, () => {
                console.log(`✅ Dashboard activo en http://${host}:${config.dashboardPortFallback}`);
                console.log(`💡 Actualiza la configuración de nginx para usar este puerto`);
                console.log(`🔒 Comunicaciones restringidas a localhost únicamente`);
            }).on('error', (err2) => {
                console.error('❌ Error al iniciar el servidor:', err2);
                process.exit(1);
            });
        } else {
            console.error('❌ Error inesperado:', err);
            process.exit(1);
        }
    });
}

// Manejo de errores no capturados
process.on('uncaughtException', (err) => {
    console.error('❌ Error no capturado:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Promesa rechazada no manejada:', reason);
});

startServer();
