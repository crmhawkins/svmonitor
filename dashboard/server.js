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

// Almacenamiento de intentos de login fallidos (en memoria, se reinicia con el servidor)
const loginAttempts = new Map();

// Función para limpiar intentos antiguos
function cleanOldAttempts() {
    const now = Date.now();
    for (const [ip, data] of loginAttempts.entries()) {
        if (now - data.lastAttempt > config.auth.lockoutDuration) {
            loginAttempts.delete(ip);
        }
    }
}

// Endpoint de login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const clientIp = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
        
        // Limpiar intentos antiguos
        cleanOldAttempts();
        
        // Validación básica de entrada (protección contra inyección)
        if (!username || typeof username !== 'string' || !password || typeof password !== 'string') {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }
        
        // Verificar si la IP está bloqueada
        const attemptData = loginAttempts.get(clientIp);
        if (attemptData && attemptData.attempts >= config.auth.maxLoginAttempts) {
            const timeLeft = Math.ceil((config.auth.lockoutDuration - (Date.now() - attemptData.lastAttempt)) / 1000 / 60);
            return res.status(429).json({ 
                error: `Demasiados intentos fallidos. Intenta nuevamente en ${timeLeft} minuto(s).` 
            });
        }
        
        // Sanitizar entrada (eliminar espacios y caracteres peligrosos)
        const sanitizedUsername = username.trim().toLowerCase();
        const sanitizedPassword = password.trim();
        
        // Validar que no contengan caracteres peligrosos (protección adicional)
        const dangerousChars = /[<>'"\\;]/;
        if (dangerousChars.test(sanitizedUsername) || dangerousChars.test(sanitizedPassword)) {
            return res.status(400).json({ error: 'Caracteres no permitidos en las credenciales' });
        }
        
        // Validar credenciales
        const isValidUsername = sanitizedUsername === config.auth.username.toLowerCase();
        const isValidPassword = sanitizedPassword === config.auth.password;
        const isValid = isValidUsername && isValidPassword;
        
        if (isValid) {
            // Login exitoso - limpiar intentos fallidos
            loginAttempts.delete(clientIp);
            
            req.session.authenticated = true;
            req.session.loginTime = Date.now();
            req.session.username = sanitizedUsername;
            
            console.log(`✅ Login exitoso desde ${clientIp} - Usuario: ${sanitizedUsername}`);
            res.json({ success: true, message: 'Login exitoso' });
        } else {
            // Login fallido - registrar intento
            if (!loginAttempts.has(clientIp)) {
                loginAttempts.set(clientIp, { attempts: 0, lastAttempt: Date.now() });
            }
            
            const attemptInfo = loginAttempts.get(clientIp);
            attemptInfo.attempts++;
            attemptInfo.lastAttempt = Date.now();
            
            const remainingAttempts = config.auth.maxLoginAttempts - attemptInfo.attempts;
            
            console.warn(`❌ Intento de login fallido desde ${clientIp} - Usuario: ${sanitizedUsername} (Intentos restantes: ${remainingAttempts})`);
            
            if (remainingAttempts <= 0) {
                res.status(429).json({ 
                    error: `Demasiados intentos fallidos. Tu IP ha sido bloqueada temporalmente.` 
                });
            } else {
                res.status(401).json({ 
                    error: `Credenciales incorrectas. Intentos restantes: ${remainingAttempts}` 
                });
            }
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
            report: null,
            logs: [] // Sistema de logs detallado
        };
        
        // Asegurar que logs existe
        if (!investigation.logs) {
            investigation.logs = [];
        }
        
        // Función helper para agregar logs
        function addLog(type, message, data = null) {
            const logEntry = {
                timestamp: Date.now(),
                type: type, // 'info', 'analyze', 'ai_request', 'ai_response', 'command', 'read', 'modify', 'quarantine', 'error'
                message: message,
                data: data
            };
            investigation.logs.push(logEntry);
            io.emit('soc_investigation_update', investigation);
        }
        
        addLog('info', '🔍 Iniciando investigación automática SOC', { investigationId });
        
        socInvestigations.unshift(investigation);
        if (socInvestigations.length > 50) {
            socInvestigations.pop();
        }
        
        // Recopilar datos sospechosos recientes
        addLog('analyze', '📊 Recopilando datos sospechosos del sistema', {
            timeWindow: 'Últimos 5 minutos',
            sources: ['processes', 'files', 'network', 'crontab']
        });
        
        // Recopilar datos sospechosos con más detalle y contexto
        const recentProcesses = logStorage.processes.filter(p => p.timestamp > Date.now() - 300000).slice(-30);
        const recentFiles = logStorage.files.filter(f => f.timestamp > Date.now() - 300000).slice(-30);
        const recentNetwork = logStorage.network.filter(n => n.timestamp > Date.now() - 300000).slice(-30);
        const recentCrontab = logStorage.crontab.filter(c => c.timestamp > Date.now() - 300000).slice(-20);
        
        // Preparar datos estructurados y detallados para la IA
        const suspiciousData = {
            resumen: {
                total_procesos: recentProcesses.length,
                total_archivos: recentFiles.length,
                total_conexiones: recentNetwork.length,
                total_crontab: recentCrontab.length,
                ventana_tiempo: 'Últimos 5 minutos',
                timestamp: new Date().toISOString()
            },
            procesos_sospechosos: recentProcesses.map(p => ({
                pid: p.pid,
                comando: p.command,
                cpu: p.cpu,
                memoria: p.mem,
                tiempo_ejecucion: p.time,
                razon_sospechosa: p.reason,
                usuario: p.user || 'desconocido',
                timestamp: new Date(p.timestamp).toISOString(),
                detalles_completos: p
            })),
            archivos_modificados: recentFiles.map(f => ({
                ruta: f.filePath || f.detail?.split(' ')[0] || f.detail || 'desconocido',
                evento: f.events || 'MODIFY',
                riesgo: f.risk || 'medium',
                timestamp: new Date(f.timestamp || f.ts || Date.now()).toISOString(),
                proceso_modificador: f.process ? {
                    pid: f.process.pid,
                    comando: f.process.command,
                    usuario: f.process.user
                } : null,
                detalles_completos: f
            })),
            conexiones_red: recentNetwork.map(n => ({
                conexion: n.detail || n.data || (typeof n === 'string' ? n : JSON.stringify(n)),
                timestamp: new Date(n.timestamp || Date.now()).toISOString(),
                riesgo: n.risk || 'medium',
                detalles_completos: n
            })),
            tareas_crontab: recentCrontab.map(c => ({
                usuario: c.user || 'desconocido',
                tarea: c.cron || c.command || 'desconocido',
                timestamp: new Date(c.timestamp || Date.now()).toISOString(),
                detalles_completos: c
            })),
            contexto_sistema: {
                sistema_operativo: process.platform,
                timestamp_analisis: new Date().toISOString(),
                total_logs_almacenados: {
                    procesos: logStorage.processes.length,
                    archivos: logStorage.files.length,
                    red: logStorage.network.length,
                    crontab: logStorage.crontab.length
                }
            }
        };
        
        addLog('analyze', '✅ Datos recopilados', {
            procesos: suspiciousData.procesos_sospechosos.length,
            archivos: suspiciousData.archivos_modificados.length,
            conexiones: suspiciousData.conexiones_red.length,
            crontab: suspiciousData.tareas_crontab.length
        });
        
        // Generar prompt para IA con comandos de investigación
        addLog('ai_request', '🤖 Preparando solicitud a IA para generar comandos de investigación', {
            model: config.aiApi.defaultModel,
            dataSummary: {
                procesos: suspiciousData.procesos_sospechosos.length,
                archivos: suspiciousData.archivos_modificados.length,
                conexiones: suspiciousData.conexiones_red.length,
                crontab: suspiciousData.tareas_crontab.length
            },
            datos_detallados: 'Incluyendo información completa de cada elemento'
        });
        
        const investigationPrompt = `Eres un analista SOC experto especializado en análisis forense de Linux. Analiza DETALLADAMENTE estos datos sospechosos y genera comandos de investigación específicos y precisos.

IMPORTANTE: 
- SOLO genera comandos de INVESTIGACIÓN, NUNCA de acción destructiva o eliminación
- Los comandos deben ser seguros y solo para análisis
- Formato: cada comando en una línea separada precedido de "CMD:"
- Analiza CADA proceso, archivo, conexión y tarea específicamente
- Genera comandos específicos basados en los datos reales proporcionados

DATOS SOSPECHOSOS DETECTADOS (ANÁLISIS DETALLADO REQUERIDO):

RESUMEN:
- Procesos sospechosos: ${suspiciousData.resumen.total_procesos}
- Archivos modificados: ${suspiciousData.resumen.total_archivos}
- Conexiones de red: ${suspiciousData.resumen.total_conexiones}
- Tareas crontab: ${suspiciousData.resumen.total_crontab}
- Ventana de tiempo: ${suspiciousData.resumen.ventana_tiempo}

DATOS COMPLETOS:
${JSON.stringify(suspiciousData, null, 2)}

INSTRUCCIONES DE GENERACIÓN DE COMANDOS:

Para CADA proceso sospechoso (${suspiciousData.procesos_sospechosos.length}):
- Genera comandos para investigar el PID específico: ps, lsof, strace, cat /proc/PID/...
- Analiza el comando ejecutado y sus argumentos
- Verifica conexiones de red del proceso
- Revisa archivos abiertos por el proceso

Para CADA archivo modificado (${suspiciousData.archivos_modificados.length}):
- Genera comandos para analizar la ruta específica: stat, file, strings, md5sum, sha256sum
- Verifica permisos y propietario
- Busca firmas maliciosas en el contenido
- Analiza el proceso que lo modificó (si está disponible)

Para CADA conexión de red (${suspiciousData.conexiones_red.length}):
- Genera comandos para investigar la conexión: ss, netstat, lsof -i
- Identifica el proceso asociado
- Verifica la dirección IP y puerto
- Analiza el tráfico si es posible

Para CADA tarea crontab (${suspiciousData.tareas_crontab.length}):
- Genera comandos para verificar la tarea: crontab -u usuario -l, cat /etc/cron*
- Analiza el comando programado
- Verifica archivos relacionados

COMANDOS ADICIONALES:
- Buscar binarios/ejecutables ocultos en rutas sospechosas (/tmp, /var/tmp, /dev/shm)
- Verificar procesos relacionados o hijos
- Analizar logs del sistema relacionados
- Buscar archivos con permisos sospechosos

Responde SOLO con los comandos en formato:
CMD: comando1
CMD: comando2
CMD: comando3
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
                    addLog('ai_response', '📥 Respuesta recibida de IA', {
                        responseLength: data.length
                    });
                    
                    const response = JSON.parse(data);
                    
                    // Verificar si hay error en la respuesta (modelo no encontrado, etc.)
                    if (response.error) {
                        const isModelNotFound = response.error.includes('not found') || response.error.includes('model');
                        
                        addLog('error', '❌ Error de la IA', {
                            error: response.error,
                            modelo_solicitado: config.aiApi.defaultModel,
                            es_error_modelo: isModelNotFound,
                            response_completa: response
                        });
                        
                        investigation.status = 'error';
                        
                        if (isModelNotFound) {
                            investigation.report = `ERROR: El modelo '${config.aiApi.defaultModel}' no está disponible en el servidor de IA.\n\n` +
                                `SOLUCIÓN:\n` +
                                `1. Instala el modelo en tu servidor de IA ejecutando:\n` +
                                `   ollama pull ${config.aiApi.defaultModel}\n\n` +
                                `2. O cambia el modelo en config.js o mediante la variable de entorno AI_MODEL\n\n` +
                                `Modelos alternativos disponibles pueden ser: mistral, llama2, codellama, qwen2.5:7b`;
                        } else {
                            investigation.report = `Error de la IA: ${response.error}`;
                        }
                        
                        io.emit('soc_investigation_update', investigation);
                        return;
                    }
                    
                    if (response.success && response.respuesta) {
                        addLog('ai_response', '✅ Respuesta de IA procesada correctamente', {
                            responseLength: response.respuesta.length,
                            respuesta_preview: response.respuesta.substring(0, 300)
                        });
                        
                        // Extraer comandos de la respuesta (múltiples formatos)
                        let commands = response.respuesta.split('\n')
                            .filter(line => line.trim().startsWith('CMD:'))
                            .map(line => line.replace('CMD:', '').trim())
                            .filter(cmd => cmd.length > 0);
                        
                        // Si no hay comandos con formato CMD:, intentar extraer de otras formas
                        if (commands.length === 0) {
                            const lines = response.respuesta.split('\n').filter(l => l.trim());
                            lines.forEach(line => {
                                // Buscar líneas que parecen comandos
                                const trimmedLine = line.trim();
                                // Comandos que empiezan con $ o #
                                if (trimmedLine.match(/^(\$|#)\s+[a-zA-Z]/)) {
                                    const cmd = trimmedLine.replace(/^(\$|#)\s+/, '').trim();
                                    if (cmd.length > 0 && !commands.includes(cmd)) {
                                        commands.push(cmd);
                                    }
                                }
                                // Comandos comunes de Linux
                                else if (trimmedLine.match(/^(ps|grep|kill|ls|cat|find|chmod|chown|rm|mv|cp|tar|wget|curl|netstat|ss|lsof|iptables|ufw|systemctl|service|journalctl|strings|file|stat|strace|tcpdump|nmap|whois|dig|ping|top|htop|df|du|free|last|history|crontab|passwd|useradd|userdel|su|id|whoami|w|who|uptime|uname|hostname|ip|ifconfig|route|mount|umount|rsync|scp|ssh|sudo)\s+/)) {
                                    if (trimmedLine.length > 3 && !commands.includes(trimmedLine)) {
                                        commands.push(trimmedLine);
                                    }
                                }
                            });
                        }
                        
                        addLog('ai_response', `📝 Comandos generados por IA: ${commands.length}`, {
                            commands: commands,
                            total_comandos: commands.length,
                            formato_original: response.respuesta.substring(0, 500)
                        });
                        
                        if (commands.length > 0) {
                            investigation.commands = commands;
                            investigation.status = 'commands_generated';
                            
                            // Ejecutar comandos de investigación
                            executeInvestigationCommands(investigation, commands);
                        } else {
                            addLog('error', '❌ IA no generó comandos válidos', {
                                respuesta_completa: response.respuesta,
                                respuesta_length: response.respuesta.length
                            });
                            investigation.status = 'error';
                            investigation.report = `La IA no generó comandos válidos. Respuesta recibida: ${response.respuesta.substring(0, 1000)}`;
                            io.emit('soc_investigation_update', investigation);
                        }
                    } else {
                        addLog('error', '❌ IA no generó respuesta válida', {
                            response: response,
                            success: response.success,
                            tiene_respuesta: !!response.respuesta,
                            error: response.error || 'Sin error específico'
                        });
                        investigation.status = 'error';
                        investigation.report = `Error al generar comandos de investigación. ${response.error ? 'Error: ' + response.error : 'La IA no devolvió una respuesta válida.'}`;
                        io.emit('soc_investigation_update', investigation);
                    }
                } catch (error) {
                    addLog('error', '❌ Error procesando respuesta de IA', {
                        error: error.message,
                        stack: error.stack
                    });
                    console.error('Error procesando respuesta de IA:', error);
                    investigation.status = 'error';
                    investigation.report = 'Error al generar comandos de investigación';
                    io.emit('soc_investigation_update', investigation);
                }
            });
        });
        
        aiRequest.on('error', (error) => {
            addLog('error', '❌ Error al conectar con IA', {
                error: error.message,
                code: error.code
            });
            console.error('Error en investigación SOC:', error);
            investigation.status = 'error';
            investigation.report = 'Error al conectar con IA';
            io.emit('soc_investigation_update', investigation);
        });
        
        addLog('ai_request', '📤 Enviando solicitud a IA', {
            url: config.aiApi.url,
            promptLength: investigationPrompt.length
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
    // Función helper para agregar logs (reutilizar si existe, sino crear nueva)
    const addLog = investigation.logs ? (type, message, data = null) => {
        const logEntry = {
            timestamp: Date.now(),
            type: type,
            message: message,
            data: data
        };
        investigation.logs.push(logEntry);
        io.emit('soc_investigation_update', investigation);
    } : () => {}; // Si no hay sistema de logs, función vacía
    
    addLog('info', '⚙️ Iniciando ejecución de comandos de investigación', {
        totalCommands: commands.length
    });
    
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
        
        addLog('command', `🔧 Ejecutando comando ${i + 1}/${commands.length}`, {
            command: command,
            index: i + 1,
            total: commands.length
        });
        
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
                    const chunk = data.toString();
                    output += chunk;
                    investigation.currentCommandOutput = output;
                    
                    addLog('read', `📖 Leyendo salida del comando (${chunk.length} bytes)`, {
                        command: command,
                        chunkLength: chunk.length,
                        totalOutputLength: output.length
                    });
                    
                    // Emitir actualización en tiempo real
                    io.emit('soc_investigation_update', investigation);
                });
            }
            
            // Capturar errores
            if (childProcess.stderr) {
                childProcess.stderr.on('data', (data) => {
                    const chunk = data.toString();
                    errorOutput += chunk;
                    investigation.currentCommandOutput = output + '\n[ERROR]\n' + errorOutput;
                    
                    addLog('read', `⚠️ Leyendo errores del comando (${chunk.length} bytes)`, {
                        command: command,
                        errorChunk: chunk.substring(0, 200) // Primeros 200 caracteres
                    });
                    
                    io.emit('soc_investigation_update', investigation);
                });
            }
            
            childProcess.on('close', (code) => {
                addLog('command', `✅ Comando ${i + 1} finalizado`, {
                    command: command,
                    exitCode: code,
                    outputLength: output.length,
                    errorLength: errorOutput.length,
                    status: code === 0 ? 'completado' : 'error'
                });
                
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
                addLog('analyze', `🔍 Analizando salida del comando en busca de binarios/ejecutables`, {
                    command: command,
                    outputLength: output.length
                });
                
                const allOutput = output + errorOutput;
                const binaryMatches = allOutput.match(/\/[^\s]+\s*$/gm) || 
                                     allOutput.match(/\/[a-zA-Z0-9\/\._-]+/g) || [];
                
                addLog('analyze', `📋 Binarios potenciales encontrados: ${binaryMatches.length}`, {
                    matches: binaryMatches.slice(0, 10) // Primeros 10
                });
                
                if (binaryMatches.length > 0) {
                    binaryMatches.forEach(binaryPath => {
                        const cleanPath = binaryPath.trim().replace(/[^\w\/\.-]/g, '');
                        if (cleanPath.startsWith('/') && fs.existsSync(cleanPath)) {
                            try {
                                const stats = fs.statSync(cleanPath);
                                if (stats.isFile() && (stats.mode & parseInt('111', 8))) {
                                    addLog('quarantine', `🔒 Archivo ejecutable detectado, poniendo en cuarentena`, {
                                        file: cleanPath,
                                        size: stats.size,
                                        mode: stats.mode.toString(8)
                                    });
                                    // Es ejecutable, copiar a cuarentena
                                    quarantineFile(cleanPath, investigation.id, quarantined);
                                }
                            } catch (err) {
                                addLog('error', `❌ Error al verificar archivo: ${cleanPath}`, {
                                    error: err.message
                                });
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
                addLog('error', `❌ Error al ejecutar comando`, {
                    command: command,
                    error: error.message,
                    code: error.code
                });
                
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
    
    addLog('info', '✅ Ejecución de comandos completada', {
        totalCommands: commands.length,
        successful: findings.filter(f => f.status === 'completado').length,
        failed: findings.filter(f => f.status === 'error').length,
        quarantined: quarantined.length
    });
    
    io.emit('soc_investigation_update', investigation);
    
    // Generar reporte final
    generateSOCReport(investigation);
}

// Poner archivo en cuarentena
function quarantineFile(filePath, investigationId, quarantinedArray) {
    try {
        const fileName = path.basename(filePath);
        const quarantinePath = path.join(config.soc.quarantinePath, `${investigationId}_${Date.now()}_${fileName}`);
        
        // Obtener información del archivo original
        const stats = fs.statSync(filePath);
        
        // Copiar archivo a cuarentena
        fs.copyFileSync(filePath, quarantinePath);
        
        // Cambiar permisos para que no sea ejecutable
        fs.chmodSync(quarantinePath, 0o644);
        
        const quarantineInfo = {
            original: filePath,
            quarantined: quarantinePath,
            timestamp: Date.now(),
            size: stats.size,
            originalMode: stats.mode.toString(8)
        };
        
        quarantinedArray.push(quarantineInfo);
        
        // Agregar log si la investigación tiene sistema de logs
        const investigation = socInvestigations.find(inv => inv.id === investigationId);
        if (investigation && investigation.logs) {
            const addLog = (type, message, data = null) => {
                investigation.logs.push({
                    timestamp: Date.now(),
                    type: type,
                    message: message,
                    data: data
                });
            };
            addLog('modify', `🔒 Archivo puesto en cuarentena`, quarantineInfo);
        }
        
        console.log(`🔒 Archivo en cuarentena: ${filePath} -> ${quarantinePath}`);
    } catch (error) {
        console.error(`Error al poner en cuarentena ${filePath}:`, error);
        const investigation = socInvestigations.find(inv => inv.id === investigationId);
        if (investigation && investigation.logs) {
            investigation.logs.push({
                timestamp: Date.now(),
                type: 'error',
                message: `❌ Error al poner archivo en cuarentena`,
                data: { filePath, error: error.message }
            });
        }
    }
}

// Generar reporte de investigación
async function generateSOCReport(investigation) {
    const addLog = investigation.logs ? (type, message, data = null) => {
        investigation.logs.push({
            timestamp: Date.now(),
            type: type,
            message: message,
            data: data
        });
        io.emit('soc_investigation_update', investigation);
    } : () => {};
    
    addLog('info', '📄 Iniciando generación de reporte final', {
        findings: investigation.findings.length,
        quarantined: investigation.quarantined.length
    });
    
    try {
        // Preparar datos detallados para el reporte
        const findingsSummary = investigation.findings.map(f => ({
            comando: f.command,
            estado: f.status,
            codigo_salida: f.exitCode,
            salida_relevante: f.output ? f.output.substring(0, 1000) : '',
            error: f.error || null,
            timestamp: new Date(f.timestamp).toISOString()
        }));
        
        const quarantinedSummary = investigation.quarantined.map(q => ({
            archivo_original: q.original,
            archivo_cuarentena: q.quarantined,
            timestamp: new Date(q.timestamp).toISOString()
        }));
        
        const reportPrompt = `Eres un analista SOC senior. Genera un reporte de investigación profesional y detallado basado en estos hallazgos:

ID Investigación: ${investigation.id}
Fecha: ${new Date(investigation.timestamp).toISOString()}
Comandos ejecutados: ${investigation.commands.length}
Hallazgos encontrados: ${investigation.findings.length}
Archivos en cuarentena: ${investigation.quarantined.length}

DETALLES DE COMANDOS EJECUTADOS:
${JSON.stringify(findingsSummary, null, 2)}

ARCHIVOS EN CUARENTENA:
${JSON.stringify(quarantinedSummary, null, 2)}

COMANDOS ORIGINALES GENERADOS:
${investigation.commands.join('\n')}

Genera un reporte ESTRUCTURADO Y DETALLADO con las siguientes secciones:

1. RESUMEN EJECUTIVO
   - Resumen de la investigación
   - Nivel de amenaza identificado
   - Hallazgos principales

2. INDICADORES DE COMPROMISO (IOCs)
   - Procesos sospechosos identificados
   - Archivos maliciosos encontrados
   - Conexiones de red anómalas
   - Tareas programadas maliciosas

3. ANÁLISIS DETALLADO
   - Análisis de cada comando ejecutado y sus resultados
   - Interpretación de los hallazgos
   - Correlación entre eventos

4. ARCHIVOS EN CUARENTENA
   - Lista de archivos aislados
   - Razón de la cuarentena
   - Recomendaciones de análisis adicional

5. RECOMENDACIONES DE MITIGACIÓN
   - Pasos específicos para contener la amenaza
   - Comandos de limpieza (NO ejecutar automáticamente)
   - Medidas preventivas
   - Monitoreo continuo recomendado

Responde en español, de forma profesional y estructurada.`;

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
                    addLog('ai_response', '📥 Respuesta de IA para reporte recibida', {
                        responseLength: data.length
                    });
                    
                    const response = JSON.parse(data);
                    if (response.success && response.respuesta) {
                        investigation.report = response.respuesta;
                        investigation.reportGenerated = true;
                        
                        addLog('modify', '📄 Reporte generado por IA', {
                            reportLength: response.respuesta.length
                        });
                        
                        // Guardar reporte en archivo
                        try {
                            const reportPath = path.join(config.soc.reportsPath, `report_${investigation.id}.txt`);
                            fs.writeFileSync(reportPath, investigation.report);
                            
                            addLog('modify', '💾 Reporte guardado en archivo', {
                                path: reportPath
                            });
                            
                            console.log(`📄 Reporte SOC guardado: ${reportPath}`);
                        } catch (fileError) {
                            addLog('error', '❌ Error guardando reporte en archivo', {
                                error: fileError.message
                            });
                            console.error('Error guardando reporte en archivo:', fileError);
                        }
                        
                        addLog('info', '✅ Reporte generado y guardado exitosamente', {
                            reportLength: investigation.report.length
                        });
                        
                        // Log final de resumen
                        addLog('info', '🎯 Investigación SOC completada exitosamente', {
                            totalLogs: investigation.logs.length,
                            totalCommands: investigation.commands.length,
                            totalFindings: investigation.findings.length,
                            totalQuarantined: investigation.quarantined.length,
                            reportGenerated: true,
                            duration: Math.round((Date.now() - investigation.timestamp) / 1000) + ' segundos'
                        });
                        
                        // Emitir actualización para mostrar el reporte
                        io.emit('soc_investigation_update', investigation);
                    } else {
                        addLog('error', '❌ IA no generó reporte válido', {
                            response: response
                        });
                        // Si la IA no respondió correctamente, generar reporte básico
                        investigation.report = `REPORTE DE INVESTIGACIÓN SOC\n\n` +
                            `ID: ${investigation.id}\n` +
                            `Fecha: ${new Date(investigation.timestamp).toISOString()}\n` +
                            `Estado: ${investigation.status}\n\n` +
                            `Comandos ejecutados: ${investigation.commands.length}\n` +
                            `Hallazgos: ${investigation.findings.length}\n` +
                            `Archivos en cuarentena: ${investigation.quarantined.length}\n\n` +
                            `RESULTADOS:\n${JSON.stringify(investigation.findings, null, 2)}\n\n` +
                            `ARCHIVOS EN CUARENTENA:\n${JSON.stringify(investigation.quarantined, null, 2)}`;
                        investigation.reportGenerated = true;
                        addLog('info', '✅ Reporte básico generado automáticamente');
                        io.emit('soc_investigation_update', investigation);
                    }
                } catch (error) {
                    addLog('error', '❌ Error al procesar respuesta de IA para reporte', {
                        error: error.message,
                        stack: error.stack
                    });
                    console.error('Error generando reporte:', error);
                    // Generar reporte básico en caso de error
                    investigation.report = `REPORTE DE INVESTIGACIÓN SOC (Generado automáticamente)\n\n` +
                        `ID: ${investigation.id}\n` +
                        `Fecha: ${new Date(investigation.timestamp).toISOString()}\n` +
                        `Error al generar reporte con IA: ${error.message}\n\n` +
                        `Comandos ejecutados: ${investigation.commands.length}\n` +
                        `Hallazgos: ${investigation.findings.length}\n` +
                        `Archivos en cuarentena: ${investigation.quarantined.length}\n\n` +
                        `RESULTADOS:\n${JSON.stringify(investigation.findings, null, 2)}`;
                    investigation.reportGenerated = true;
                    addLog('info', '✅ Reporte básico generado tras error');
                    io.emit('soc_investigation_update', investigation);
                }
            });
        });
        
        aiRequest.on('error', (error) => {
            console.error('Error al generar reporte:', error);
            // Generar reporte básico en caso de error de conexión
            investigation.report = `REPORTE DE INVESTIGACIÓN SOC (Generado automáticamente)\n\n` +
                `ID: ${investigation.id}\n` +
                `Fecha: ${new Date(investigation.timestamp).toISOString()}\n` +
                `Error al conectar con IA: ${error.message}\n\n` +
                `Comandos ejecutados: ${investigation.commands.length}\n` +
                `Hallazgos: ${investigation.findings.length}\n` +
                `Archivos en cuarentena: ${investigation.quarantined.length}\n\n` +
                `RESULTADOS:\n${JSON.stringify(investigation.findings, null, 2)}\n\n` +
                `ARCHIVOS EN CUARENTENA:\n${JSON.stringify(investigation.quarantined, null, 2)}`;
            investigation.reportGenerated = true;
            io.emit('soc_investigation_update', investigation);
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
