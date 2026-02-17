const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const { exec } = require('child_process');
const nodemailer = require('nodemailer');
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

// Almacenamiento persistente de logs en memoria (OPTIMIZADO)
const logStorage = {
    network: [],
    files: [],
    processes: [],
    crontab: []
};

// Función para agregar log y mantener límite (OPTIMIZADA para ahorrar RAM)
function addLog(type, data) {
    if (!logStorage[type]) return;
    
    // Limitar tamaño de datos almacenados (evitar objetos grandes)
    const optimizedData = {
        timestamp: Date.now()
    };
    
    // Solo almacenar campos esenciales para ahorrar RAM
    if (data.detail) optimizedData.detail = String(data.detail).substring(0, 200); // Limitar a 200 chars
    if (data.filePath) optimizedData.filePath = String(data.filePath).substring(0, 200);
    if (data.risk) optimizedData.risk = data.risk;
    if (data.pid) optimizedData.pid = data.pid;
    if (data.command) optimizedData.command = String(data.command).substring(0, 150);
    if (data.cpu !== undefined) optimizedData.cpu = data.cpu;
    if (data.mem !== undefined) optimizedData.mem = data.mem;
    if (data.events) optimizedData.events = data.events;
    if (data.ts) optimizedData.ts = data.ts;
    
    logStorage[type].push(optimizedData);
    
    // Mantener solo los últimos N registros (más agresivo)
    const maxSize = config.logBufferSize[type] || 50;
    if (logStorage[type].length > maxSize) {
        // Eliminar los más antiguos (más eficiente que slice)
        logStorage[type].splice(0, logStorage[type].length - maxSize);
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

// Crear carpeta de archivos capturados
function initCaptureDirectory() {
    const capturePath = config.quickCapture?.capturePath || '/var/sentinel/captured';
    if (!fs.existsSync(capturePath)) {
        fs.mkdirSync(capturePath, { recursive: true });
        console.log(`📁 Creada carpeta de captura: ${capturePath}`);
    }
}

initCaptureDirectory();

// Almacenamiento de archivos capturados (OPTIMIZADO: límite estricto)
const capturedFiles = [];
const MAX_CAPTURED_FILES = 200; // Máximo 200 archivos en memoria

// ==================== GESTIÓN DE ESPACIO EN DISCO ====================

// Calcular tamaño total de una carpeta (OPTIMIZADO: usa du para ser más rápido y eficiente)
function getFolderSize(folderPath) {
    try {
        if (!fs.existsSync(folderPath)) return 0;
        
        // Usar du para calcular tamaño (más rápido y eficiente en memoria)
        return new Promise((resolve) => {
            exec(`du -sb "${folderPath}" 2>/dev/null | cut -f1`, { timeout: 10000 }, (error, stdout) => {
                if (error || !stdout) {
                    // Fallback: calcular manualmente pero limitando profundidad
                    let totalSize = 0;
                    try {
                        const files = fs.readdirSync(folderPath);
                        let count = 0;
                        for (const file of files) {
                            if (count++ > 10000) break; // Limitar a 10000 archivos para no saturar
                            const filePath = path.join(folderPath, file);
                            try {
                                const stats = fs.statSync(filePath);
                                if (stats.isFile()) {
                                    totalSize += stats.size;
                                }
                            } catch (err) {
                                // Ignorar errores
                            }
                        }
                    } catch (err) {
                        // Ignorar
                    }
                    resolve(totalSize);
                } else {
                    resolve(parseInt(stdout.trim()) || 0);
                }
            });
        });
    } catch (error) {
        console.error(`❌ Error al calcular tamaño de ${folderPath}:`, error.message);
        return Promise.resolve(0);
    }
}

// Versión síncrona optimizada (para uso inmediato)
function getFolderSizeSync(folderPath) {
    try {
        if (!fs.existsSync(folderPath)) return 0;
        
        let totalSize = 0;
        const files = fs.readdirSync(folderPath);
        let count = 0;
        const maxFiles = 5000; // Limitar para no saturar memoria
        
        for (const file of files) {
            if (count++ > maxFiles) break;
            const filePath = path.join(folderPath, file);
            try {
                const stats = fs.statSync(filePath);
                if (stats.isFile()) {
                    totalSize += stats.size;
                }
            } catch (err) {
                // Ignorar errores
            }
        }
        
        return totalSize;
    } catch (error) {
        return 0;
    }
}

// Limpiar carpeta cuando exceda el límite (OPTIMIZADO: más agresivo)
function cleanupFolder(folderPath, maxSize, cleanupPercentage = 0.3) {
    try {
        if (!fs.existsSync(folderPath)) return null;
        
        // Usar versión síncrona optimizada para verificación rápida
        const currentSize = getFolderSizeSync(folderPath);
        
        if (currentSize <= maxSize) {
            return null; // No necesita limpieza
        }
        
        console.log(`🧹 Limpiando carpeta ${folderPath}: ${(currentSize / 1024 / 1024 / 1024).toFixed(2)}GB (límite: ${(maxSize / 1024 / 1024 / 1024).toFixed(2)}GB)`);
        
        // Obtener archivos con límite para no saturar memoria
        const files = [];
        const items = fs.readdirSync(folderPath);
        let itemCount = 0;
        const maxItems = 10000; // Limitar procesamiento
        
        for (const item of items) {
            if (itemCount++ > maxItems) break;
            const itemPath = path.join(folderPath, item);
            try {
                const stats = fs.statSync(itemPath);
                if (stats.isFile()) {
                    files.push({
                        path: itemPath,
                        name: item,
                        size: stats.size,
                        mtime: stats.mtime.getTime()
                    });
                }
            } catch (err) {
                // Ignorar errores
            }
        }
        
        // Ordenar por fecha (más antiguos primero)
        files.sort((a, b) => a.mtime - b.mtime);
        
        // Calcular cuánto espacio necesitamos liberar (más agresivo: 30%)
        const targetSize = maxSize * (1 - cleanupPercentage);
        let freedSpace = 0;
        let deletedCount = 0;
        let currentTotal = currentSize;
        
        for (const file of files) {
            if (currentTotal <= targetSize) {
                break; // Ya liberamos suficiente espacio
            }
            
            try {
                fs.unlinkSync(file.path);
                freedSpace += file.size;
                currentTotal -= file.size;
                deletedCount++;
            } catch (err) {
                console.warn(`⚠️ No se pudo eliminar ${file.path}:`, err.message);
            }
        }
        
        console.log(`✅ Limpieza completada: ${deletedCount} archivos eliminados, ${(freedSpace / 1024 / 1024 / 1024).toFixed(2)}GB liberados`);
        
        return { deletedCount, freedSpace };
    } catch (error) {
        console.error(`❌ Error al limpiar carpeta ${folderPath}:`, error.message);
        return null;
    }
}

// Verificar y limpiar todas las carpetas con límites (OPTIMIZADO: verificación más estricta)
function checkAndCleanupFolders() {
    const maxSize = 2 * 1024 * 1024 * 1024; // 2GB estricto
    
    // Limpiar carpeta de cuarentena
    if (config.soc.quarantinePath) {
        const currentSize = getFolderSizeSync(config.soc.quarantinePath);
        if (currentSize >= maxSize * 0.9) { // Limpiar cuando llegue al 90% (1.8GB)
            cleanupFolder(config.soc.quarantinePath, maxSize, 0.3);
        }
    }
    
    // Limpiar carpeta de reportes
    if (config.soc.reportsPath) {
        const currentSize = getFolderSizeSync(config.soc.reportsPath);
        if (currentSize >= maxSize * 0.9) {
            cleanupFolder(config.soc.reportsPath, maxSize, 0.3);
        }
    }
    
    // Limpiar carpeta de capturas
    if (config.quickCapture?.capturePath) {
        const currentSize = getFolderSizeSync(config.quickCapture.capturePath);
        if (currentSize >= maxSize * 0.9) {
            cleanupFolder(config.quickCapture.capturePath, maxSize, 0.3);
        }
    }
}

// ==================== SISTEMA DE CORREO ELECTRÓNICO ====================

let emailTransporter = null;
let lastEmailSent = {
    criticalActivity: 0,
    massDowntime: 0,
    diskSpace: 0,
    rapidGrowth: 0
};

// Ruta del archivo de configuración de correo
const emailConfigPath = path.join(__dirname, '..', 'email-config.json');

// Cargar configuración de correo desde archivo
function loadEmailConfig() {
    try {
        if (fs.existsSync(emailConfigPath)) {
            const data = fs.readFileSync(emailConfigPath, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Error al cargar configuración de correo:', error);
    }
    // Retornar configuración por defecto
    return {
        enabled: config.email.enabled,
        smtp: config.email.smtp,
        from: config.email.from,
        to: config.email.to,
        alerts: config.email.alerts
    };
}

// Guardar configuración de correo en archivo
function saveEmailConfig(emailConfig) {
    try {
        fs.writeFileSync(emailConfigPath, JSON.stringify(emailConfig, null, 2), 'utf8');
        // Actualizar config en memoria
        config.email = emailConfig;
        // Reinicializar transportador
        initEmailTransporter();
        return true;
    } catch (error) {
        console.error('Error al guardar configuración de correo:', error);
        return false;
    }
}

// Inicializar transportador de correo
function initEmailTransporter() {
    // Cargar configuración desde archivo si existe
    const emailConfig = loadEmailConfig();
    
    if (!emailConfig.enabled) {
        console.log('📧 Sistema de correo deshabilitado');
        emailTransporter = null;
        return;
    }
    
    try {
        if (!emailConfig.smtp || !emailConfig.smtp.host || !emailConfig.smtp.auth || !emailConfig.smtp.auth.user) {
            console.log('📧 Sistema de correo no configurado correctamente');
            emailTransporter = null;
            return;
        }
        
        emailTransporter = nodemailer.createTransport({
            host: emailConfig.smtp.host,
            port: emailConfig.smtp.port,
            secure: emailConfig.smtp.secure,
            auth: {
                user: emailConfig.smtp.auth.user,
                pass: emailConfig.smtp.auth.pass
            }
        });
        
        console.log('📧 Sistema de correo inicializado');
    } catch (error) {
        console.error('❌ Error al inicializar correo:', error.message);
        emailTransporter = null;
    }
}

// Enviar correo de alerta
async function sendEmailAlert(subject, message, type = 'alert') {
    const emailConfig = loadEmailConfig();
    if (!emailConfig.enabled || !emailTransporter) {
        return false;
    }
    
    // Prevenir spam: máximo 1 correo por tipo cada 15 minutos
    const now = Date.now();
    const cooldown = 15 * 60 * 1000; // 15 minutos
    
    if (lastEmailSent[type] && (now - lastEmailSent[type]) < cooldown) {
        return false; // Demasiado pronto para enviar otro correo del mismo tipo
    }
    
    try {
        const mailOptions = {
            from: emailConfig.from,
            to: emailConfig.to.join(', '),
            subject: `🚨 SENTINEL: ${subject}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: #0d1117; color: #c9d1d9; padding: 20px; border-radius: 8px;">
                        <h2 style="color: #da3633; margin-top: 0;">🚨 Alerta de Seguridad - Sentinel</h2>
                        <div style="background: #161b22; padding: 15px; border-radius: 6px; margin: 15px 0;">
                            <h3 style="color: #58a6ff; margin-top: 0;">${subject}</h3>
                            <div style="color: #c9d1d9; line-height: 1.6; white-space: pre-wrap;">${message}</div>
                        </div>
                        <div style="color: #8b949e; font-size: 0.85rem; margin-top: 20px; border-top: 1px solid #30363d; padding-top: 15px;">
                            <p>Este es un mensaje automático del sistema Sentinel de monitoreo de seguridad.</p>
                            <p>Timestamp: ${new Date().toISOString()}</p>
                        </div>
                    </div>
                </div>
            `,
            text: `${subject}\n\n${message}\n\nTimestamp: ${new Date().toISOString()}`
        };
        
        await emailTransporter.sendMail(mailOptions);
        lastEmailSent[type] = now;
        console.log(`📧 Correo enviado: ${subject}`);
        return true;
    } catch (error) {
        console.error('❌ Error al enviar correo:', error.message);
        return false;
    }
}

initEmailTransporter();

// Monitoreo de espacio en disco
let lastDiskCheck = {
    timestamp: Date.now(),
    sizes: {},
    diskUsage: {}
};

function checkDiskSpace() {
    return new Promise((resolve) => {
        // Verificar espacio en disco usando df
        exec('df -h / | tail -1', { timeout: 5000 }, (error, stdout) => {
            if (error) {
                console.warn('⚠️ No se pudo verificar espacio en disco:', error.message);
                resolve(null);
                return;
            }
            
            // Parsear salida de df: Filesystem Size Used Avail Use% Mounted on
            const parts = stdout.trim().split(/\s+/);
            if (parts.length >= 5) {
                const usagePercent = parseInt(parts[4].replace('%', ''));
                const used = parts[2];
                const available = parts[3];
                
                resolve({
                    usagePercent,
                    used,
                    available,
                    timestamp: Date.now()
                });
            } else {
                resolve(null);
            }
        });
    });
}

function checkFolderSizes() {
    const sizes = {};
    const monitoredPaths = config.diskMonitoring?.monitoredPaths || [];
    
    monitoredPaths.forEach(folderPath => {
        if (fs.existsSync(folderPath)) {
            sizes[folderPath] = getFolderSizeSync(folderPath);
        }
    });
    
    return sizes;
}

async function monitorDiskSpace() {
    try {
        const diskInfo = await checkDiskSpace();
        const folderSizes = checkFolderSizes();
        
        const now = Date.now();
        const timeDiff = now - lastDiskCheck.timestamp;
        const hoursDiff = timeDiff / (1000 * 60 * 60);
        
        // Verificar crecimiento rápido de carpetas
        if (lastDiskCheck.sizes && Object.keys(lastDiskCheck.sizes).length > 0) {
            for (const [folderPath, currentSize] of Object.entries(folderSizes)) {
                const lastSize = lastDiskCheck.sizes[folderPath] || 0;
                const growth = currentSize - lastSize;
                const growthMB = growth / (1024 * 1024);
                const growthMBPerHour = hoursDiff > 0 ? growthMB / hoursDiff : 0;
                
                const rapidGrowthThreshold = config.diskMonitoring?.rapidGrowthThreshold || 1000; // 1GB por hora
                
                if (growthMBPerHour > rapidGrowthThreshold && hoursDiff > 0.1) {
                    const message = `🚨 CRECIMIENTO RÁPIDO DETECTADO: ${folderPath} está creciendo a ${growthMBPerHour.toFixed(2)}MB/hora (${(growthMB / 1024).toFixed(2)}GB en las últimas ${hoursDiff.toFixed(2)} horas)`;
                    console.warn(message);
                    io.emit('disk_alert', {
                        type: 'rapid_growth',
                        folder: folderPath,
                        growthMBPerHour: growthMBPerHour,
                        currentSize: currentSize,
                        message: message
                    });
                    
                    // Enviar correo si está habilitado
                    if (config.email.enabled && config.email.alerts.rapidGrowth) {
                        sendEmailAlert(
                            'Crecimiento Rápido de Archivos Detectado',
                            `Se detectó crecimiento rápido en: ${folderPath}\n\nCrecimiento: ${growthMBPerHour.toFixed(2)}MB/hora\nTamaño actual: ${(currentSize / 1024 / 1024 / 1024).toFixed(2)}GB\nCrecimiento en período: ${(growthMB / 1024).toFixed(2)}GB en ${hoursDiff.toFixed(2)} horas\n\nEsto puede indicar actividad sospechosa o un problema en el sistema.`,
                            'rapidGrowth'
                        );
                    }
                }
            }
        }
        
        // Verificar uso de disco
        if (diskInfo) {
            const alertThreshold = config.diskMonitoring?.alertThreshold || 85;
            const criticalThreshold = config.diskMonitoring?.criticalThreshold || 95;
            
            if (diskInfo.usagePercent >= criticalThreshold) {
                const message = `🚨 CRÍTICO: Disco al ${diskInfo.usagePercent}% de capacidad (${diskInfo.used} usado, ${diskInfo.available} disponible)`;
                console.error(message);
                io.emit('disk_alert', {
                    type: 'critical',
                    usagePercent: diskInfo.usagePercent,
                    used: diskInfo.used,
                    available: diskInfo.available,
                    message: message
                });
            } else if (diskInfo.usagePercent >= alertThreshold) {
                const message = `⚠️ ALERTA: Disco al ${diskInfo.usagePercent}% de capacidad (${diskInfo.used} usado, ${diskInfo.available} disponible)`;
                console.warn(message);
                io.emit('disk_alert', {
                    type: 'warning',
                    usagePercent: diskInfo.usagePercent,
                    used: diskInfo.used,
                    available: diskInfo.available,
                    message: message
                });
            }
        }
        
        // Actualizar último check
        lastDiskCheck = {
            timestamp: now,
            sizes: folderSizes,
            diskUsage: diskInfo
        };
        
        // Ejecutar limpieza automática si es necesario
        checkAndCleanupFolders();
        
    } catch (error) {
        console.error('❌ Error en monitoreo de espacio:', error);
    }
}

// Iniciar monitoreo de espacio en disco
if (config.diskMonitoring?.checkInterval) {
    // Ejecutar inmediatamente
    monitorDiskSpace();
    
    // Luego cada X minutos
    setInterval(monitorDiskSpace, config.diskMonitoring.checkInterval);
    console.log(`📊 Monitoreo de espacio en disco iniciado (cada ${config.diskMonitoring.checkInterval / 1000 / 60} minutos)`);
}

// Función para serializar JSON de forma segura sin desbordar memoria
function safeJSONStringify(obj, space = 0) {
    try {
        let depth = 0;
        const maxDepth = 5;
        
        // Limitar tamaño total del JSON (aproximadamente 500KB)
        const result = JSON.stringify(obj, (key, value) => {
            // Limitar profundidad (aproximado)
            if (key && typeof value === 'object' && value !== null) {
                depth++;
                if (depth > maxDepth) {
                    depth--;
                    return '"[Max depth reached]"';
                }
            }
            
            // Limitar tamaño de strings largos
            if (typeof value === 'string' && value.length > 1000) {
                return value.substring(0, 1000) + '...[truncated]';
            }
            
            // Limitar arrays grandes
            if (Array.isArray(value) && value.length > 50) {
                return value.slice(0, 50).concat(`[${value.length - 50} more items]`);
            }
            
            // Limitar objetos grandes
            if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                const keys = Object.keys(value);
                if (keys.length > 20) {
                    const limited = {};
                    let count = 0;
                    for (const k of keys) {
                        if (count++ < 20) {
                            limited[k] = value[k];
                        }
                    }
                    limited['...[truncated]'] = `${keys.length - 20} more properties`;
                    return limited;
                }
            }
            
            return value;
        }, space);
        
        // Si el resultado es muy grande, truncarlo
        if (result && result.length > 500000) {
            return result.substring(0, 500000) + '\n...[JSON truncated due to size]';
        }
        
        return result || '{}';
    } catch (error) {
        console.error('Error en safeJSONStringify:', error);
        return `{"error": "JSON serialization failed: ${error.message}"}`;
    }
}

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
            procesos_sospechosos: recentProcesses.slice(0, 20).map(p => ({
                pid: p.pid,
                comando: p.command,
                cpu: p.cpu,
                memoria: p.mem,
                tiempo_ejecucion: p.time,
                razon_sospechosa: p.reason,
                usuario: p.user || 'desconocido',
                timestamp: new Date(p.timestamp).toISOString()
            })),
            archivos_modificados: recentFiles.slice(0, 20).map(f => ({
                ruta: f.filePath || f.detail?.split(' ')[0] || f.detail || 'desconocido',
                evento: f.events || 'MODIFY',
                riesgo: f.risk || 'medium',
                timestamp: new Date(f.timestamp || f.ts || Date.now()).toISOString(),
                proceso_modificador: f.process ? {
                    pid: f.process.pid,
                    comando: f.process.command,
                    usuario: f.process.user
                } : null
            })),
            conexiones_red: recentNetwork.slice(0, 20).map(n => ({
                conexion: n.detail || n.data || (typeof n === 'string' ? n : String(n).substring(0, 200)),
                timestamp: new Date(n.timestamp || Date.now()).toISOString(),
                riesgo: n.risk || 'medium'
            })),
            tareas_crontab: recentCrontab.slice(0, 15).map(c => ({
                usuario: c.user || 'desconocido',
                tarea: c.cron || c.command || 'desconocido',
                timestamp: new Date(c.timestamp || Date.now()).toISOString()
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
${safeJSONStringify(suspiciousData, 2)}

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
        
        // Limpiar comando antes de ejecutar (eliminar caracteres especiales y formato)
        let cleanCommand = command.trim();
        // Eliminar prefijos como $, #, CMD:, etc.
        cleanCommand = cleanCommand.replace(/^[\$#]\s*/, '').replace(/^CMD:\s*/i, '').trim();
        // Eliminar comentarios entre paréntesis al final
        cleanCommand = cleanCommand.replace(/\s*\([^)]*\)\s*$/, '').trim();
        // Eliminar múltiples espacios
        cleanCommand = cleanCommand.replace(/\s+/g, ' ');
        
        // Validar que el comando no esté vacío
        if (!cleanCommand || cleanCommand.length < 2) {
            addLog('error', `❌ Comando inválido o vacío: "${command}"`, {
                original: command,
                cleaned: cleanCommand
            });
            investigation.currentCommandStatus = 'error';
            investigation.currentCommandOutput = `Comando inválido: "${command}"`;
            io.emit('soc_investigation_update', investigation);
            continue;
        }
        
        // Ejecutar comando con salida en tiempo real
        await new Promise((resolve) => {
            const childProcess = exec(cleanCommand, { 
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
                            // Verificar y limpiar carpeta de reportes antes de crear nuevo
                            checkAndCleanupFolders();
                            
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
// Endpoints para archivos capturados
app.get('/api/captured', requireAuth, (req, res) => {
    try {
        res.json({
            success: true,
            files: capturedFiles,
            total: capturedFiles.length
        });
    } catch (error) {
        console.error('Error al listar archivos capturados:', error);
        res.status(500).json({ error: 'Error al listar archivos capturados' });
    }
});

app.get('/api/captured/:id/download', requireAuth, (req, res) => {
    try {
        const fileId = req.params.id;
        const file = capturedFiles.find(f => f.id === fileId || f.fileName === fileId);
        
        if (!file) {
            return res.status(404).json({ error: 'Archivo no encontrado' });
        }
        
        if (!fs.existsSync(file.captured)) {
            return res.status(404).json({ error: 'Archivo físico no encontrado' });
        }
        
        res.download(file.captured, file.fileName, (err) => {
            if (err) {
                console.error('Error al descargar archivo:', err);
                res.status(500).json({ error: 'Error al descargar archivo' });
            }
        });
    } catch (error) {
        console.error('Error al descargar archivo:', error);
        res.status(500).json({ error: 'Error al descargar archivo' });
    }
});

app.post('/api/captured/:id/analyze', requireAuth, async (req, res) => {
    try {
        const fileId = req.params.id;
        const file = capturedFiles.find(f => f.id === fileId || f.fileName === fileId);
        
        if (!file) {
            return res.status(404).json({ error: 'Archivo no encontrado' });
        }
        
        if (!fs.existsSync(file.captured)) {
            return res.status(404).json({ error: 'Archivo físico no encontrado' });
        }
        
        // Leer contenido del archivo (limitado a 100KB para análisis)
        const stats = fs.statSync(file.captured);
        const maxSize = 100 * 1024; // 100KB
        let fileContent = '';
        
        if (stats.size > maxSize) {
            // Leer solo los primeros 100KB
            const buffer = Buffer.alloc(maxSize);
            const fd = fs.openSync(file.captured, 'r');
            fs.readSync(fd, buffer, 0, maxSize, 0);
            fs.closeSync(fd);
            fileContent = buffer.toString('utf8', 0, maxSize) + '\n...[Archivo truncado, tamaño total: ' + stats.size + ' bytes]';
        } else {
            fileContent = fs.readFileSync(file.captured, 'utf8');
        }
        
        // Preparar prompt para IA
        const analysisPrompt = `Eres un analista de seguridad experto. Analiza este archivo sospechoso capturado automáticamente.

INFORMACIÓN DEL ARCHIVO:
- Ruta original: ${file.original}
- Nombre: ${file.fileName}
- Tamaño: ${stats.size} bytes
- Razón de captura: ${file.reason}
- Timestamp: ${new Date(file.timestamp).toISOString()}

CONTENIDO DEL ARCHIVO:
\`\`\`
${fileContent}
\`\`\`

INSTRUCCIONES:
1. Analiza el contenido del archivo en busca de código malicioso
2. Identifica firmas de malware, backdoors, shells, etc.
3. Proporciona un análisis detallado del nivel de amenaza
4. Da recomendaciones específicas de mitigación
5. Si es código PHP, analiza funciones sospechosas como eval(), base64_decode(), gzinflate(), etc.
6. Usa etiquetas <code> para comandos y <strong> para puntos importantes

FORMATO DE MITIGACIÓN:
Para cada comando de mitigación, usa el formato:
MITIGATE: [Descripción de la acción] | [comando a ejecutar]

Ejemplo:
MITIGATE: Eliminar archivo malicioso | rm -f ${file.original}
MITIGATE: Verificar permisos del directorio | ls -la ${path.dirname(file.original)}

Responde en formato estructurado con:
- Nivel de amenaza (Bajo/Medio/Alto/Crítico)
- Tipo de malware detectado (si aplica)
- Análisis detallado
- Recomendaciones de mitigación (usando formato MITIGATE: para cada comando)`;

        // Llamar a IA
        const aiUrl = new URL(config.aiApi.url);
        const isHttps = aiUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        
        const requestData = JSON.stringify({
            prompt: analysisPrompt,
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
                        // Marcar archivo como analizado
                        file.analyzed = true;
                        file.analysis = response.respuesta;
                        file.analysisTimestamp = Date.now();
                        
                        res.json({
                            success: true,
                            analysis: response.respuesta,
                            file: file
                        });
                    } else {
                        res.status(500).json({
                            error: response.error || 'Error al analizar archivo',
                            response: response
                        });
                    }
                } catch (error) {
                    console.error('Error procesando respuesta de IA:', error);
                    res.status(500).json({ error: 'Error al procesar respuesta de IA' });
                }
            });
        });
        
        aiRequest.on('error', (error) => {
            console.error('Error al conectar con IA:', error);
            res.status(500).json({ error: 'Error al conectar con IA' });
        });
        
        aiRequest.write(requestData);
        aiRequest.end();
        
    } catch (error) {
        console.error('Error al analizar archivo:', error);
        res.status(500).json({ error: 'Error al analizar archivo' });
    }
});

// Endpoints para configuración de correo (emailConfigPath ya está definido arriba)

// Cargar configuración de correo desde archivo
function loadEmailConfig() {
    try {
        if (fs.existsSync(emailConfigPath)) {
            const data = fs.readFileSync(emailConfigPath, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Error al cargar configuración de correo:', error);
    }
    // Retornar configuración por defecto
    return {
        enabled: config.email.enabled,
        smtp: config.email.smtp,
        from: config.email.from,
        to: config.email.to,
        alerts: config.email.alerts
    };
}

// Guardar configuración de correo en archivo
function saveEmailConfig(emailConfig) {
    try {
        fs.writeFileSync(emailConfigPath, JSON.stringify(emailConfig, null, 2), 'utf8');
        // Actualizar config en memoria
        config.email = emailConfig;
        // Reinicializar transportador
        initEmailTransporter();
        return true;
    } catch (error) {
        console.error('Error al guardar configuración de correo:', error);
        return false;
    }
}

app.get('/api/email/config', requireAuth, (req, res) => {
    try {
        const emailConfig = loadEmailConfig();
        // No enviar la contraseña en la respuesta
        const safeConfig = {
            ...emailConfig,
            smtp: {
                ...emailConfig.smtp,
                auth: {
                    ...emailConfig.smtp.auth,
                    pass: emailConfig.smtp.auth.pass ? '***' : '' // Ocultar contraseña
                }
            }
        };
        res.json({ success: true, config: safeConfig });
    } catch (error) {
        console.error('Error al obtener configuración de correo:', error);
        res.status(500).json({ error: 'Error al obtener configuración' });
    }
});

app.post('/api/email/config', requireAuth, (req, res) => {
    try {
        const emailConfig = req.body;
        
        // Validación básica
        if (emailConfig.enabled) {
            if (!emailConfig.smtp || !emailConfig.smtp.host || !emailConfig.smtp.auth || !emailConfig.smtp.auth.user) {
                return res.status(400).json({ error: 'Configuración SMTP incompleta' });
            }
            if (!emailConfig.from || !emailConfig.to || emailConfig.to.length === 0) {
                return res.status(400).json({ error: 'Correo remitente y destinatarios son requeridos' });
            }
        }
        
        // Si la contraseña viene como '***', mantener la actual
        const currentConfig = loadEmailConfig();
        if (emailConfig.smtp && emailConfig.smtp.auth && emailConfig.smtp.auth.pass === '***') {
            emailConfig.smtp.auth.pass = currentConfig.smtp.auth.pass;
        }
        
        if (saveEmailConfig(emailConfig)) {
            res.json({ success: true, message: 'Configuración guardada correctamente' });
        } else {
            res.status(500).json({ error: 'Error al guardar configuración' });
        }
    } catch (error) {
        console.error('Error al guardar configuración de correo:', error);
        res.status(500).json({ error: 'Error al guardar configuración' });
    }
});

app.post('/api/email/test', requireAuth, async (req, res) => {
    try {
        const testConfig = req.body;
        
        if (!testConfig.enabled) {
            return res.status(400).json({ error: 'El sistema de correo está deshabilitado' });
        }
        
        // Crear transportador temporal para prueba
        const testTransporter = nodemailer.createTransport({
            host: testConfig.smtp.host,
            port: testConfig.smtp.port,
            secure: testConfig.smtp.secure,
            auth: testConfig.smtp.auth
        });
        
        // Enviar correo de prueba
        const mailOptions = {
            from: testConfig.from,
            to: testConfig.to.join(', '),
            subject: '🧪 Prueba de Configuración - Sentinel',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background: #0d1117; color: #c9d1d9; padding: 20px; border-radius: 8px;">
                        <h2 style="color: #3fb950; margin-top: 0;">✅ Correo de Prueba Exitoso</h2>
                        <p>Este es un correo de prueba del sistema Sentinel de monitoreo de seguridad.</p>
                        <p>Si recibes este correo, significa que la configuración SMTP es correcta.</p>
                        <div style="color: #8b949e; font-size: 0.85rem; margin-top: 20px; border-top: 1px solid #30363d; padding-top: 15px;">
                            <p>Timestamp: ${new Date().toISOString()}</p>
                        </div>
                    </div>
                </div>
            `,
            text: 'Este es un correo de prueba del sistema Sentinel. Si recibes este correo, la configuración SMTP es correcta.'
        };
        
        await testTransporter.sendMail(mailOptions);
        res.json({ success: true, message: 'Correo de prueba enviado correctamente' });
    } catch (error) {
        console.error('Error al enviar correo de prueba:', error);
        res.status(500).json({ error: `Error al enviar correo: ${error.message}` });
    }
});

// Endpoints para monitoreo de espacio en disco
app.get('/api/disk/info', requireAuth, async (req, res) => {
    try {
        const diskInfo = await checkDiskSpace();
        const folderSizes = {
            quarantine: getFolderSize(config.soc.quarantinePath),
            capture: getFolderSize(config.quickCapture?.capturePath || '/var/sentinel/captured'),
            reports: getFolderSize(config.soc.reportsPath)
        };
        
        res.json({
            success: true,
            diskUsage: diskInfo,
            folderSizes: folderSizes
        });
    } catch (error) {
        console.error('Error al obtener información de disco:', error);
        res.status(500).json({ error: 'Error al obtener información de disco' });
    }
});

app.post('/api/disk/cleanup', requireAuth, (req, res) => {
    try {
        let totalDeleted = 0;
        const results = {};
        
        // Limpiar todas las carpetas
        if (config.soc.quarantinePath) {
            const result = cleanupFolder(
                config.soc.quarantinePath,
                config.soc.maxFolderSize || (2 * 1024 * 1024 * 1024),
                config.soc.cleanupPercentage || 0.2
            );
            if (result) {
                totalDeleted += result.deletedCount || 0;
                results.quarantine = result;
            }
        }
        
        if (config.soc.reportsPath) {
            const result = cleanupFolder(
                config.soc.reportsPath,
                config.soc.maxFolderSize || (2 * 1024 * 1024 * 1024),
                config.soc.cleanupPercentage || 0.2
            );
            if (result) {
                totalDeleted += result.deletedCount || 0;
                results.reports = result;
            }
        }
        
        if (config.quickCapture?.capturePath) {
            const result = cleanupFolder(
                config.quickCapture.capturePath,
                config.quickCapture.maxFolderSize || (2 * 1024 * 1024 * 1024),
                config.quickCapture.cleanupPercentage || 0.2
            );
            if (result) {
                totalDeleted += result.deletedCount || 0;
                results.capture = result;
            }
        }
        
        res.json({
            success: true,
            freedSpace: totalDeleted,
            results: results
        });
    } catch (error) {
        console.error('Error al limpiar carpetas:', error);
        res.status(500).json({ error: 'Error al limpiar carpetas' });
    }
});

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
                
                // Detectar actividad extremadamente sospechosa (muchos archivos críticos en poco tiempo)
                const recentCriticalFiles = logStorage.files.filter(f => 
                    (f.risk === 'high' || f.risk === 'critical') && 
                    Date.now() - f.timestamp < 2 * 60 * 1000
                ).length;
                
                if (recentCriticalFiles >= 20 && config.email.enabled && config.email.alerts.criticalActivity) {
                    sendEmailAlert(
                        'Actividad Extremadamente Sospechosa: Múltiples Archivos Críticos',
                        `Se han detectado ${recentCriticalFiles} archivos con riesgo crítico o alto en los últimos 2 minutos.\n\nÚltimo archivo: ${data.filePath || 'N/A'}\nRiesgo: ${data.risk}\nEventos: ${data.events || 'N/A'}\n\nEsto puede indicar un ataque activo en curso. Se requiere investigación inmediata.`,
                        'criticalActivity'
                    );
                }
                
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
            
            // Detectar actividad extremadamente sospechosa (muchos procesos sospechosos)
            if (data.length >= 5 && config.email.enabled && config.email.alerts.criticalActivity) {
                const processesSummary = data.slice(0, 5).map(p => 
                    `- PID ${p.pid}: ${p.command || 'N/A'} (CPU: ${p.cpu || 0}%, Mem: ${p.mem || 0}%)`
                ).join('\n');
                
                sendEmailAlert(
                    'Actividad Extremadamente Sospechosa: Múltiples Procesos PHP Sospechosos',
                    `Se han detectado ${data.length} procesos PHP sospechosos simultáneamente.\n\nProcesos detectados:\n${processesSummary}${data.length > 5 ? `\n... y ${data.length - 5} más` : ''}\n\nEsto puede indicar un ataque activo o procesos maliciosos ejecutándose.`,
                    'criticalActivity'
                );
            }
            
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
            // Detectar caída generalizada de sitios
            const downSites = data.filter(site => site.status === 'down' || site.status === 'failed');
            const totalSites = data.length;
            const downPercentage = totalSites > 0 ? (downSites.length / totalSites) * 100 : 0;
            
            // Si más del 30% de los sitios están caídos, es una caída generalizada
            if (downPercentage >= 30 && config.email.enabled && config.email.alerts.massDowntime) {
                sendEmailAlert(
                    'Caída Generalizada de Sitios Web Detectada',
                    `Se ha detectado una caída generalizada de sitios web.\n\nSitios caídos: ${downSites.length} de ${totalSites} (${downPercentage.toFixed(1)}%)\n\nSitios afectados:\n${downSites.slice(0, 10).map(s => `- ${s.domain || s.name || 'N/A'}: ${s.status}`).join('\n')}${downSites.length > 10 ? `\n... y ${downSites.length - 10} más` : ''}\n\nEsto puede indicar un problema en el servidor o un ataque DDoS.`,
                    'massDowntime'
                );
            }
            
            io.emit('ui_sites', data);
        }
    });
    
    socket.on('sites_alert', (data) => {
        if (data && typeof data === 'object') {
            io.emit('ui_sites_alert', data);
        }
    });
    
    // Handler para archivos capturados rápidamente
    socket.on('file_captured', (data) => {
        console.log('🚨 Archivo sospechoso capturado:', data);
        
        // Agregar a la lista de archivos capturados
        const capturedInfo = {
            id: `CAP-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
            original: data.original,
            captured: data.captured,
            fileName: data.fileName,
            size: data.size,
            timestamp: data.timestamp,
            reason: data.reason,
            analyzed: false
        };
        
        capturedFiles.unshift(capturedInfo); // Agregar al inicio
        // Mantener solo los últimos N archivos (OPTIMIZADO: límite estricto)
        if (capturedFiles.length > MAX_CAPTURED_FILES) {
            capturedFiles.splice(MAX_CAPTURED_FILES);
        }
        
        // Detectar actividad sospechosa: muchos archivos capturados en poco tiempo
        const recentCaptures = capturedFiles.filter(f => Date.now() - f.timestamp < 5 * 60 * 1000).length;
        if (recentCaptures >= 10 && config.email.enabled && config.email.alerts.criticalActivity) {
            sendEmailAlert(
                'Actividad Extremadamente Sospechosa Detectada',
                `Se han capturado ${recentCaptures} archivos sospechosos en los últimos 5 minutos.\n\nÚltimo archivo capturado: ${data.fileName}\nRuta: ${data.original}\nRazón: ${data.reason}\n\nEsto puede indicar un ataque activo en curso.`,
                'criticalActivity'
            );
        }
        
        // Emitir a todos los clientes
        io.emit('file_captured', capturedInfo);
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

// Endpoint para ejecutar comandos de mitigación
app.post('/api/mitigation/execute', requireAuth, async (req, res) => {
    try {
        const { command, description } = req.body;
        
        if (!command || typeof command !== 'string') {
            return res.status(400).json({ error: 'Comando es requerido' });
        }
        
        // Limpiar comando
        let cleanCommand = command.trim();
        cleanCommand = cleanCommand.replace(/^[\$#]\s*/, '').replace(/^CMD:\s*/i, '').trim();
        cleanCommand = cleanCommand.replace(/\s*\([^)]*\)\s*$/, '').trim();
        cleanCommand = cleanCommand.replace(/\s+/g, ' ');
        
        if (!cleanCommand || cleanCommand.length < 2) {
            return res.status(400).json({ error: 'Comando inválido' });
        }
        
        // Validar que no sea un comando peligroso sin contexto
        const dangerousCommands = ['rm -rf /', 'mkfs', 'dd if=', 'format'];
        const isDangerous = dangerousCommands.some(dc => cleanCommand.toLowerCase().includes(dc));
        
        if (isDangerous) {
            return res.status(400).json({ 
                error: 'Comando demasiado peligroso para ejecutar automáticamente',
                command: cleanCommand
            });
        }
        
        console.log(`⚡ Ejecutando comando de mitigación: ${cleanCommand} (${description || 'Sin descripción'})`);
        
        // Ejecutar comando
        exec(cleanCommand, { 
            timeout: 30000, 
            maxBuffer: 10 * 1024 * 1024 // 10MB
        }, (error, stdout, stderr) => {
            if (error) {
                console.error(`❌ Error al ejecutar comando de mitigación: ${error.message}`);
                res.json({
                    success: false,
                    error: error.message,
                    output: stderr || stdout || '',
                    exitCode: error.code || 1,
                    command: cleanCommand
                });
            } else {
                console.log(`✅ Comando de mitigación ejecutado correctamente`);
                res.json({
                    success: true,
                    output: stdout || '',
                    error: stderr || null,
                    exitCode: 0,
                    command: cleanCommand
                });
            }
        });
        
    } catch (error) {
        console.error('Error en ejecución de comando de mitigación:', error);
        res.status(500).json({ error: 'Error al ejecutar comando: ' + error.message });
    }
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

// Endpoint para ejecutar comandos de mitigación
app.post('/api/mitigation/execute', requireAuth, async (req, res) => {
    try {
        const { command, description } = req.body;
        
        if (!command || typeof command !== 'string') {
            return res.status(400).json({ error: 'Comando es requerido' });
        }
        
        // Limpiar comando
        let cleanCommand = command.trim();
        cleanCommand = cleanCommand.replace(/^[\$#]\s*/, '').replace(/^CMD:\s*/i, '').trim();
        cleanCommand = cleanCommand.replace(/\s*\([^)]*\)\s*$/, '').trim();
        cleanCommand = cleanCommand.replace(/\s+/g, ' ');
        
        if (!cleanCommand || cleanCommand.length < 2) {
            return res.status(400).json({ error: 'Comando inválido' });
        }
        
        // Validar que no sea un comando peligroso sin contexto
        const dangerousCommands = ['rm -rf /', 'mkfs', 'dd if=', 'format'];
        const isDangerous = dangerousCommands.some(dc => cleanCommand.toLowerCase().includes(dc));
        
        if (isDangerous) {
            return res.status(400).json({ 
                error: 'Comando demasiado peligroso para ejecutar automáticamente',
                command: cleanCommand
            });
        }
        
        console.log(`⚡ Ejecutando comando de mitigación: ${cleanCommand} (${description || 'Sin descripción'})`);
        
        // Ejecutar comando
        exec(cleanCommand, { 
            timeout: 30000, 
            maxBuffer: 10 * 1024 * 1024 // 10MB
        }, (error, stdout, stderr) => {
            if (error) {
                console.error(`❌ Error al ejecutar comando de mitigación: ${error.message}`);
                res.json({
                    success: false,
                    error: error.message,
                    output: stderr || stdout || '',
                    exitCode: error.code || 1,
                    command: cleanCommand
                });
            } else {
                console.log(`✅ Comando de mitigación ejecutado correctamente`);
                res.json({
                    success: true,
                    output: stdout || '',
                    error: stderr || null,
                    exitCode: 0,
                    command: cleanCommand
                });
            }
        });
        
    } catch (error) {
        console.error('Error en ejecución de comando de mitigación:', error);
        res.status(500).json({ error: 'Error al ejecutar comando: ' + error.message });
    }
});

// Manejo de errores no capturados
process.on('uncaughtException', (err) => {
    console.error('❌ Error no capturado:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Promesa rechazada no manejada:', reason);
});

startServer();
