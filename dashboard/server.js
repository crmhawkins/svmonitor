const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const { exec } = require('child_process');
const config = require('../config');

const app = express();
const server = http.createServer(app);

// Middleware para parsear JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configurar sesiones
app.use(session({
    secret: config.auth.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Cambiar a true si usas HTTPS
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 horas
    }
}));

// Middleware de autenticación
function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated) {
        return next();
    } else {
        return res.status(401).json({ error: 'No autenticado' });
    }
}

// Almacenamiento persistente de logs en memoria
const logStorage = {
    network: [],
    files: [],
    processes: [],
    crontab: []
};

// Función para agregar log y mantener límite
function addLog(type, data) {
    if (!logStorage[type]) return;
    
    logStorage[type].push({
        ...data,
        timestamp: Date.now()
    });
    
    // Mantener solo los últimos N registros
    const maxSize = config.logBufferSize[type] || 100;
    if (logStorage[type].length > maxSize) {
        logStorage[type] = logStorage[type].slice(-maxSize);
    }
}

// Configurar Socket.IO solo para localhost
const io = new Server(server, {
    cors: {
        origin: false,
        credentials: false
    },
    transports: ['websocket', 'polling']
});

// Endpoint de login
app.post('/api/login', async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password || typeof password !== 'string') {
            return res.status(400).json({ error: 'Contraseña requerida' });
        }
        
        // Validar contraseña (comparación segura, sin SQL injection - no hay BD)
        // Sanitizar entrada para prevenir inyecciones
        const sanitizedPassword = password.trim();
        const isValid = sanitizedPassword === config.auth.password;
        
        if (isValid) {
            req.session.authenticated = true;
            req.session.loginTime = Date.now();
            res.json({ success: true, message: 'Login exitoso' });
        } else {
            res.status(401).json({ error: 'Contraseña incorrecta' });
        }
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Endpoint de logout
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Error al cerrar sesión' });
        }
        res.json({ success: true, message: 'Logout exitoso' });
    });
});

// Verificar autenticación
app.get('/api/auth/check', (req, res) => {
    res.json({ authenticated: !!(req.session && req.session.authenticated) });
});

// Servir archivos estáticos
app.use(express.static(path.join(__dirname)));

// Ruta principal - verificar autenticación
app.get('/', (req, res) => {
    if (req.session && req.session.authenticated) {
        res.sendFile(path.join(__dirname, 'index.html'));
    } else {
        res.sendFile(path.join(__dirname, 'login.html'));
    }
});

// Crear carpetas necesarias para SOC
function initSOCDirectories() {
    const dirs = [config.soc.quarantinePath, config.soc.reportsPath];
    dirs.forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
            console.log(`📁 Creada carpeta: ${dir}`);
        }
    });
}

initSOCDirectories();

// Almacenamiento de investigación SOC
const socInvestigations = [];
let suspiciousLogCount = 0;
let lastInvestigationTime = 0;

// Función para ejecutar investigación automática SOC
async function runSOCInvestigation() {
    try {
        console.log('🔍 Iniciando investigación automática SOC...');
        
        const investigationId = `INV-${Date.now()}`;
        const investigation = {
            id: investigationId,
            timestamp: Date.now(),
            status: 'investigating',
            findings: [],
            commands: [],
            quarantined: [],
            report: null
        };
        
        socInvestigations.unshift(investigation);
        if (socInvestigations.length > 50) {
            socInvestigations.pop();
        }
        
        // Recopilar datos sospechosos recientes
        const suspiciousData = {
            processes: logStorage.processes.filter(p => p.timestamp > Date.now() - 300000).slice(-20),
            files: logStorage.files.filter(f => (f.risk === 'high' || f.risk === 'critical') && f.timestamp > Date.now() - 300000).slice(-20),
            network: logStorage.network.filter(n => n.timestamp > Date.now() - 300000).slice(-20),
            crontab: logStorage.crontab.filter(c => c.timestamp > Date.now() - 300000).slice(-10)
        };
        
        // Generar prompt para IA con comandos de investigación
        const investigationPrompt = `Eres un analista SOC experto. Analiza estos datos sospechosos y genera comandos de investigación específicos para Linux.

IMPORTANTE: 
- SOLO genera comandos de INVESTIGACIÓN, NUNCA de acción o eliminación
- Los comandos deben ser seguros y solo para análisis
- Formato: cada comando en una línea separada precedido de "CMD:"

Datos sospechosos detectados:
${JSON.stringify(suspiciousData, null, 2)}

Genera comandos para:
1. Investigar procesos sospechosos (ps, lsof, strace)
2. Analizar archivos modificados (find, stat, file, strings)
3. Buscar binarios/ejecutables ocultos (find con -executable, locate)
4. Verificar conexiones de red (netstat, ss, lsof -i)
5. Analizar crontab sospechoso (crontab -l, cat /etc/cron*)

Responde SOLO con los comandos en formato:
CMD: comando1
CMD: comando2
...`;

        // Llamar a IA para generar comandos
        const aiUrl = new URL(config.aiApi.url);
        const isHttps = aiUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        
        const requestData = JSON.stringify({
            prompt: investigationPrompt,
            modelo: config.aiApi.defaultModel
        });
        
        const options = {
            hostname: aiUrl.hostname,
            port: aiUrl.port || (isHttps ? 443 : 80),
            path: aiUrl.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(requestData),
                'x-api-key': config.aiApi.apiKey
            },
            timeout: 120000
        };
        
        const aiRequest = httpModule.request(options, (aiResponse) => {
            let data = '';
            
            aiResponse.on('data', (chunk) => {
                data += chunk;
            });
            
            aiResponse.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    if (response.success && response.respuesta) {
                        // Extraer comandos de la respuesta
                        const commands = response.respuesta.split('\n')
                            .filter(line => line.trim().startsWith('CMD:'))
                            .map(line => line.replace('CMD:', '').trim())
                            .filter(cmd => cmd.length > 0);
                        
                        investigation.commands = commands;
                        investigation.status = 'commands_generated';
                        
                        // Ejecutar comandos de investigación
                        executeInvestigationCommands(investigation, commands);
                    }
                } catch (error) {
                    console.error('Error procesando respuesta de IA:', error);
                    investigation.status = 'error';
                    investigation.report = 'Error al generar comandos de investigación';
                    io.emit('soc_investigation_update', investigation);
                }
            });
        });
        
        aiRequest.on('error', (error) => {
            console.error('Error en investigación SOC:', error);
            investigation.status = 'error';
            investigation.report = 'Error al conectar con IA';
            io.emit('soc_investigation_update', investigation);
        });
        
        aiRequest.write(requestData);
        aiRequest.end();
        
        io.emit('soc_investigation_update', investigation);
        
    } catch (error) {
        console.error('Error en investigación SOC:', error);
    }
}

// Ejecutar comandos de investigación
async function executeInvestigationCommands(investigation, commands) {
    investigation.status = 'executing';
    investigation.currentCommand = null;
    investigation.currentCommandIndex = 0;
    investigation.totalCommands = commands.length;
    investigation.commandProgress = [];
    io.emit('soc_investigation_update', investigation);
    
    const findings = [];
    const quarantined = [];
    
    // Ejecutar comandos secuencialmente para mostrar progreso
    for (let i = 0; i < commands.length; i++) {
        const command = commands[i];
        
        // Actualizar estado: comando actual
        investigation.currentCommand = command;
        investigation.currentCommandIndex = i + 1;
        investigation.currentCommandStatus = 'ejecutando';
        investigation.currentCommandOutput = '';
        
        io.emit('soc_investigation_update', investigation);
        
        // Ejecutar comando con salida en tiempo real
        await new Promise((resolve) => {
            const childProcess = exec(command, { 
                timeout: 30000, 
                maxBuffer: 10 * 1024 * 1024 // 10MB
            });
            
            let output = '';
            let errorOutput = '';
            
            // Capturar salida estándar
            if (childProcess.stdout) {
                childProcess.stdout.on('data', (data) => {
                    output += data.toString();
                    investigation.currentCommandOutput = output;
                    // Emitir actualización en tiempo real
                    io.emit('soc_investigation_update', investigation);
                });
            }
            
            // Capturar errores
            if (childProcess.stderr) {
                childProcess.stderr.on('data', (data) => {
                    errorOutput += data.toString();
                    investigation.currentCommandOutput = output + '\n[ERROR]\n' + errorOutput;
                    io.emit('soc_investigation_update', investigation);
                });
            }
            
            childProcess.on('close', (code) => {
                const commandResult = {
                    command: command,
                    index: i + 1,
                    output: output,
                    error: errorOutput || (code !== 0 ? `Comando terminó con código ${code}` : null),
                    exitCode: code,
                    timestamp: Date.now(),
                    status: code === 0 ? 'completado' : 'error'
                };
                
                findings.push(commandResult);
                investigation.commandProgress.push(commandResult);
                
                // Buscar binarios/ejecutables en la salida
                const allOutput = output + errorOutput;
                const binaryMatches = allOutput.match(/\/[^\s]+\s*$/gm) || 
                                     allOutput.match(/\/[a-zA-Z0-9\/\._-]+/g) || [];
                
                if (binaryMatches.length > 0) {
                    binaryMatches.forEach(binaryPath => {
                        const cleanPath = binaryPath.trim().replace(/[^\w\/\.-]/g, '');
                        if (cleanPath.startsWith('/') && fs.existsSync(cleanPath)) {
                            try {
                                const stats = fs.statSync(cleanPath);
                                if (stats.isFile() && (stats.mode & parseInt('111', 8))) {
                                    // Es ejecutable, copiar a cuarentena
                                    quarantineFile(cleanPath, investigation.id, quarantined);
                                }
                            } catch (err) {
                                // Ignorar errores al verificar archivo
                            }
                        }
                    });
                }
                
                // Actualizar estado del comando
                investigation.currentCommandStatus = code === 0 ? 'completado' : 'error';
                investigation.currentCommandOutput = output + (errorOutput ? '\n[ERROR]\n' + errorOutput : '');
                
                io.emit('soc_investigation_update', investigation);
                
                // Pequeña pausa entre comandos para mejor visualización
                setTimeout(resolve, 500);
            });
            
            childProcess.on('error', (error) => {
                const commandResult = {
                    command: command,
                    index: i + 1,
                    output: '',
                    error: error.message,
                    exitCode: -1,
                    timestamp: Date.now(),
                    status: 'error'
                };
                
                findings.push(commandResult);
                investigation.commandProgress.push(commandResult);
                investigation.currentCommandStatus = 'error';
                investigation.currentCommandOutput = `Error: ${error.message}`;
                
                io.emit('soc_investigation_update', investigation);
                setTimeout(resolve, 500);
            });
        });
    }
    
    // Limpiar comando actual
    investigation.currentCommand = null;
    investigation.currentCommandStatus = null;
    investigation.currentCommandOutput = null;
    investigation.findings = findings;
    investigation.quarantined = quarantined;
    investigation.status = 'completed';
    
    io.emit('soc_investigation_update', investigation);
    
    // Generar reporte final
    generateSOCReport(investigation);
}

// Poner archivo en cuarentena
function quarantineFile(filePath, investigationId, quarantinedArray) {
    try {
        const fileName = path.basename(filePath);
        const quarantinePath = path.join(config.soc.quarantinePath, `${investigationId}_${Date.now()}_${fileName}`);
        
        // Copiar archivo a cuarentena
        fs.copyFileSync(filePath, quarantinePath);
        
        // Cambiar permisos para que no sea ejecutable
        fs.chmodSync(quarantinePath, 0o644);
        
        quarantinedArray.push({
            original: filePath,
            quarantined: quarantinePath,
            timestamp: Date.now()
        });
        
        console.log(`🔒 Archivo en cuarentena: ${filePath} -> ${quarantinePath}`);
    } catch (error) {
        console.error(`Error al poner en cuarentena ${filePath}:`, error);
    }
}

// Generar reporte de investigación
async function generateSOCReport(investigation) {
    try {
        const reportPrompt = `Genera un reporte de investigación SOC profesional basado en estos hallazgos:

ID Investigación: ${investigation.id}
Comandos ejecutados: ${investigation.commands.length}
Hallazgos: ${investigation.findings.length}
Archivos en cuarentena: ${investigation.quarantined.length}

Hallazgos:
${JSON.stringify(investigation.findings, null, 2)}

Archivos en cuarentena:
${JSON.stringify(investigation.quarantined, null, 2)}

Genera un reporte estructurado con:
1. Resumen ejecutivo
2. Indicadores de compromiso (IOCs)
3. Análisis de procesos
4. Archivos sospechosos encontrados
5. Recomendaciones de mitigación (sin ejecutar, solo recomendaciones)`;

        const aiUrl = new URL(config.aiApi.url);
        const isHttps = aiUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        
        const requestData = JSON.stringify({
            prompt: reportPrompt,
            modelo: config.aiApi.defaultModel
        });
        
        const options = {
            hostname: aiUrl.hostname,
            port: aiUrl.port || (isHttps ? 443 : 80),
            path: aiUrl.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(requestData),
                'x-api-key': config.aiApi.apiKey
            },
            timeout: 120000
        };
        
        const aiRequest = httpModule.request(options, (aiResponse) => {
            let data = '';
            
            aiResponse.on('data', (chunk) => {
                data += chunk;
            });
            
            aiResponse.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    if (response.success && response.respuesta) {
                        investigation.report = response.respuesta;
                        
                        // Guardar reporte en archivo
                        const reportPath = path.join(config.soc.reportsPath, `report_${investigation.id}.txt`);
                        fs.writeFileSync(reportPath, investigation.report);
                        
                        io.emit('soc_investigation_update', investigation);
                    }
                } catch (error) {
                    console.error('Error generando reporte:', error);
                }
            });
        });
        
        aiRequest.on('error', (error) => {
            console.error('Error al generar reporte:', error);
        });
        
        aiRequest.write(requestData);
        aiRequest.end();
        
    } catch (error) {
        console.error('Error en generación de reporte:', error);
    }
}

// Verificar si se debe iniciar investigación
function checkSOCInvestigation() {
    const now = Date.now();
    const timeSinceLastInvestigation = now - lastInvestigationTime;
    
    if (suspiciousLogCount >= config.soc.investigationThreshold && 
        timeSinceLastInvestigation >= config.soc.investigationInterval) {
        suspiciousLogCount = 0;
        lastInvestigationTime = now;
        runSOCInvestigation();
    }
}

// Iniciar verificación periódica
setInterval(() => {
    checkSOCInvestigation();
}, config.soc.investigationInterval);

// Endpoint para obtener investigaciones SOC
app.get('/api/soc/investigations', requireAuth, (req, res) => {
    res.json(socInvestigations);
});

// Endpoint para descargar archivo de cuarentena
app.get('/api/soc/quarantine/:filename', requireAuth, (req, res) => {
    try {
        const filename = path.basename(req.params.filename); // Prevenir path traversal
        const filePath = path.join(config.soc.quarantinePath, filename);
        
        if (fs.existsSync(filePath)) {
            res.download(filePath, filename);
        } else {
            res.status(404).json({ error: 'Archivo no encontrado' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Error al descargar archivo' });
    }
});

// Endpoint para listar archivos en cuarentena
app.get('/api/soc/quarantine', requireAuth, (req, res) => {
    try {
        const files = fs.readdirSync(config.soc.quarantinePath)
            .map(file => {
                const filePath = path.join(config.soc.quarantinePath, file);
                const stats = fs.statSync(filePath);
                return {
                    name: file,
                    size: stats.size,
                    created: stats.birthtime,
                    path: `/api/soc/quarantine/${file}`
                };
            });
        res.json(files);
    } catch (error) {
        res.status(500).json({ error: 'Error al listar archivos' });
    }
});

// Endpoint para análisis de IA (chat manual - sin autenticación para facilitar uso)
app.post('/api/ai/analyze', async (req, res) => {
    try {
        const { prompt, modelo, context } = req.body;
        
        if (!prompt) {
            return res.status(400).json({ error: 'Prompt es requerido' });
        }
        
        const model = modelo || config.aiApi.defaultModel;
        const aiUrl = new URL(config.aiApi.url);
        const isHttps = aiUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        
        const requestData = JSON.stringify({
            prompt: prompt,
            modelo: model
        });
        
        const options = {
            hostname: aiUrl.hostname,
            port: aiUrl.port || (isHttps ? 443 : 80),
            path: aiUrl.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(requestData),
                'x-api-key': config.aiApi.apiKey
            },
            timeout: 120000 // 2 minutos timeout
        };
        
        const aiRequest = httpModule.request(options, (aiResponse) => {
            let data = '';
            
            aiResponse.on('data', (chunk) => {
                data += chunk;
            });
            
            aiResponse.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    res.json(response);
                } catch (error) {
                    console.error('Error parsing AI response:', error);
                    res.status(500).json({ error: 'Error al procesar respuesta de IA', details: error.message });
                }
            });
        });
        
        aiRequest.on('error', (error) => {
            console.error('Error en petición a IA:', error);
            res.status(500).json({ error: 'Error al conectar con el servidor de IA', details: error.message });
        });
        
        aiRequest.on('timeout', () => {
            aiRequest.destroy();
            res.status(504).json({ error: 'Timeout al conectar con el servidor de IA' });
        });
        
        aiRequest.write(requestData);
        aiRequest.end();
        
    } catch (error) {
        console.error('Error en endpoint de IA:', error);
        res.status(500).json({ error: 'Error interno del servidor', details: error.message });
    }
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
    
    // Enviar historial completo al cliente cuando se conecta
    socket.emit('log_history', {
        network: logStorage.network,
        files: logStorage.files,
        processes: logStorage.processes,
        crontab: logStorage.crontab
    });
    
    socket.on('health_stats', (data) => {
        if (data && typeof data === 'object') {
            io.emit('ui_health', data);
        }
    });
    
    socket.on('network_alert', (data) => {
        if (data) {
            // Guardar en almacenamiento persistente
            const lines = data.split('\n').filter(l => l.trim());
            lines.forEach(line => {
                addLog('network', { data: line });
            });
            
            io.emit('ui_network', data);
        }
    });
    
    socket.on('file_change', (data) => {
        if (data && typeof data === 'object') {
            // Guardar en almacenamiento persistente
            addLog('files', data);
            
            // Incrementar contador de logs sospechosos si es de riesgo alto
            if (data.risk === 'high' || data.risk === 'critical') {
                suspiciousLogCount++;
                checkSOCInvestigation();
            }
            
            io.emit('ui_file', data);
        }
    });
    
    socket.on('process_alert', (data) => {
        if (data && Array.isArray(data)) {
            // Guardar en almacenamiento persistente
            data.forEach(process => {
                addLog('processes', process);
            });
            
            // Incrementar contador de logs sospechosos
            suspiciousLogCount += data.length;
            checkSOCInvestigation();
            
            io.emit('ui_process', data);
        }
    });
    
    socket.on('crontab_alert', (data) => {
        if (data && Array.isArray(data)) {
            // Guardar en almacenamiento persistente
            data.forEach(cron => {
                addLog('crontab', cron);
            });
            
            // Incrementar contador si hay tareas sospechosas
            if (data.length > 0) {
                suspiciousLogCount += data.length;
                checkSOCInvestigation();
            }
            
            io.emit('ui_crontab', data);
        }
    });
    
    socket.on('sites_status', (data) => {
        if (data && Array.isArray(data)) {
            io.emit('ui_sites', data);
        }
    });
    
    socket.on('sites_alert', (data) => {
        if (data && typeof data === 'object') {
            io.emit('ui_sites_alert', data);
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
        console.log(`🌐 Nginx debe redirigir el puerto 80 a este puerto interno`);
        console.log(`📋 Configura nginx para svmonitor.herasoft.ai -> http://127.0.0.1:${port}`);
        console.log(`🔒 Comunicaciones restringidas a localhost únicamente`);
        console.log(`\n💡 Para verificar que funciona:`);
        console.log(`   curl http://127.0.0.1:${port}`);
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
