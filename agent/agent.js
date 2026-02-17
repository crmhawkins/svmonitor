const { exec, spawn } = require('child_process');
const http = require('http');
const https = require('https');
const io = require('socket.io-client');
const os = require('os');
const fs = require('fs');
const path = require('path');
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
let processInterval = null;
let fileScanInterval = null;
let crontabInterval = null;
let siteCheckInterval = null;
let fileWatcher = null;
let discoveredSites = new Map(); // Cache de sitios descubiertos
let siteStatusHistory = new Map(); // Historial de estados de sitios para detectar cambios

// Sistema de control de CPU (límite al 10%)
let cpuThrottleMultiplier = 1.0; // Multiplicador de intervalos (1.0 = normal, 2.0 = doble intervalo)
let lastCpuCheck = Date.now();
let cpuUsageHistory = []; // Historial de uso de CPU (últimos 10 checks)
const MAX_CPU_HISTORY = 10;

// Función para verificar y ajustar uso de CPU
function checkAndThrottleCPU() {
    if (!config.cpuLimit || !config.cpuLimit.enableAdaptiveThrottling) return;
    
    try {
        let currentCpu = 0;
        
        if (isWindows) {
            // Windows: usar process.cpuUsage() relativo
            const usage = process.cpuUsage();
            const total = (usage.user + usage.system) / 1000000; // Convertir a segundos
            currentCpu = total * 100; // Aproximación
        } else {
            // Linux: usar loadavg (más preciso)
            const loadavg = os.loadavg()[0] || 0;
            const cpuCount = os.cpus().length;
            currentCpu = (loadavg / cpuCount) * 100; // Porcentaje de CPU
        }
        
        // Agregar al historial
        cpuUsageHistory.push(currentCpu);
        if (cpuUsageHistory.length > MAX_CPU_HISTORY) {
            cpuUsageHistory.shift();
        }
        
        // Calcular promedio de los últimos checks
        const avgCpu = cpuUsageHistory.reduce((a, b) => a + b, 0) / cpuUsageHistory.length;
        
        // Ajustar throttling basado en uso promedio
        if (avgCpu > config.cpuLimit.maxCpuPercent) {
            // Excediendo límite: aumentar multiplicador
            cpuThrottleMultiplier = Math.min(
                cpuThrottleMultiplier * 1.2, 
                config.cpuLimit.throttleMultiplier
            );
            console.log(`⚠️ CPU alto (${avgCpu.toFixed(2)}%), aumentando throttling a ${cpuThrottleMultiplier.toFixed(2)}x`);
        } else if (avgCpu < config.cpuLimit.maxCpuPercent * 0.7) {
            // Por debajo del 70% del límite: reducir multiplicador gradualmente
            cpuThrottleMultiplier = Math.max(
                cpuThrottleMultiplier * 0.95, 
                config.cpuLimit.minIntervalMultiplier || 1.0
            );
        }
        
        lastCpuCheck = Date.now();
    } catch (error) {
        console.error('❌ Error al verificar CPU:', error);
    }
}

// Función para obtener intervalo ajustado según throttling
function getThrottledInterval(baseInterval) {
    return Math.floor(baseInterval * cpuThrottleMultiplier);
}

// Iniciar monitoreo de CPU
if (config.cpuLimit && config.cpuLimit.enableAdaptiveThrottling) {
    setInterval(checkAndThrottleCPU, config.cpuLimit.checkInterval || 5000);
    console.log(`📊 Control de CPU activado: límite ${config.cpuLimit.maxCpuPercent}%`);
}

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

    // Alertas de red mejoradas - detectar conexiones salientes desde PHP
    // OPTIMIZACIÓN: Monitoreo de red más eficiente (combinar comandos) - CON THROTTLING
    networkInterval = setInterval(() => {
        try {
            // Pausa inicial para reducir carga
            setTimeout(() => {
                if (isLinux) {
                    // OPTIMIZACIÓN: Un solo comando en lugar de dos, timeout más corto
                    exec("ss -antp 2>/dev/null | grep -E 'php.*:(443|80|25)' | grep -E 'ESTAB|SYN-SENT' | grep -v '127.0.0.1' | grep -v '::1' | head -20", 
                        { timeout: 1000 }, 
                        (err, stdout) => {
                            if (!err && stdout && stdout.trim()) {
                                socket.emit('network_alert', stdout);
                            }
                        }
                    );
                } else {
                    // Windows: usar netstat (optimizado)
                    exec('netstat -an | findstr "ESTABLISHED SYN_SENT php"', { timeout: 800 }, (err, stdout) => {
                        if (!err && stdout) {
                            const suspicious = stdout.split('\n').filter(line => 
                                line.includes('php') || line.includes('SYN_SENT')
                            ).slice(0, 20).join('\n'); // Limitar a 20 líneas
                            if (suspicious) {
                                socket.emit('network_alert', suspicious);
                            }
                        }
                    });
                }
            }, 100); // Pausa de 100ms antes de ejecutar
        } catch (error) {
            console.error('❌ Error al verificar red:', error);
        }
    }, getThrottledInterval(config.networkCheckInterval));

    // Monitoreo de procesos PHP sospechosos
    if (isLinux) {
        // OPTIMIZACIÓN: Monitoreo de procesos más eficiente - CON THROTTLING
        processInterval = setInterval(() => {
            try {
                // Pausa inicial para reducir carga
                setTimeout(() => {
                    // OPTIMIZACIÓN: Filtrar directamente en el comando ps (más rápido), limitar resultados
                    exec("ps aux | grep '[p]hp' | awk '$3>20 || $4>50 || $10>\"00:30\" {print $2, $3, $4, $9, $10, $11, $12, $13, $14, $15, $16, $17}' | head -30", 
                        { timeout: 1200 }, 
                        (err, stdout) => {
                            if (!err && stdout) {
                                const processes = [];
                                const lines = stdout.trim().split('\n').filter(l => l.trim());
                                
                                // OPTIMIZACIÓN: Limitar procesamiento a máximo 30 procesos (reducido de 50)
                                const maxProcesses = 30;
                                lines.slice(0, maxProcesses).forEach((line, index) => {
                                    // Pausa cada 10 procesos para reducir CPU
                                    if (index > 0 && index % 10 === 0) {
                                        setTimeout(() => {}, 10);
                                    }
                                    
                                    const parts = line.trim().split(/\s+/);
                                    if (parts.length >= 11) {
                                        const pid = parts[0];
                                        const cpu = parseFloat(parts[1]) || 0;
                                        const mem = parseFloat(parts[2]) || 0;
                                        const time = parts[3];
                                        const command = parts.slice(10).join(' ');
                                        
                                        // Detectar procesos sospechosos (simplificado)
                                        let suspicious = false;
                                        let reason = '';
                                        
                                        // CPU alta constante
                                        if (cpu > 20) {
                                            suspicious = true;
                                            reason = `CPU alto: ${cpu}%`;
                                        }
                                        
                                        // Tiempo de ejecución largo
                                        if (time && time.includes(':')) {
                                            const [hours, mins] = time.split(':').map(Number);
                                            if (hours > 0 || (hours === 0 && mins > 30)) {
                                                suspicious = true;
                                                reason = reason ? `${reason}, Tiempo: ${time}` : `Tiempo largo: ${time}`;
                                            }
                                        }
                                        
                                        // Comandos sospechosos (solo verificar si ya es sospechoso)
                                        if (suspicious && (command.includes('base64') || command.includes('eval') || 
                                            command.includes('system') || command.includes('exec'))) {
                                            reason = reason ? `${reason}, Comando sospechoso` : 'Comando sospechoso';
                                        }
                                        
                                        // Excluir procesos del backend/frontend propios
                                        const isExcluded = config.excludedProcesses.some(excluded => 
                                            command.includes(excluded)
                                        );
                                        
                                        if (suspicious && !isExcluded) {
                                            processes.push({
                                                pid,
                                                cpu,
                                                mem,
                                                time,
                                                command: command.substring(0, 200), // Limitar tamaño
                                                reason
                                            });
                                        }
                                    }
                            });
                            
                                if (processes.length > 0) {
                                    socket.emit('process_alert', processes);
                                }
                            }
                        }
                    );
                }, 150); // Pausa de 150ms antes de ejecutar
            } catch (error) {
                console.error('❌ Error al verificar procesos:', error);
            }
        }, getThrottledInterval(config.processCheckInterval));
    }

    // Escaneo periódico de firmas maliciosas en archivos PHP
    if (isLinux) {
        fileScanInterval = setInterval(() => {
            try {
                const watchPath = process.env.WATCH_PATH || '/var/www/vhosts';
                
                // Buscar eval( y base64_decode en archivos PHP
                // OPTIMIZACIÓN: Limitar búsqueda a archivos modificados recientemente y reducir resultados
                exec(`find ${watchPath} -name "*.php" -mtime -1 -exec grep -l 'eval(' {} \\; 2>/dev/null | head -5`, 
                    { timeout: 8000 }, 
                    (err, stdout) => {
                        if (!err && stdout) {
                            const files = stdout.trim().split('\n').filter(f => f);
                            files.forEach(file => {
                                socket.emit('file_change', {
                                    detail: `Firma maliciosa detectada: eval(`,
                                    filePath: file,
                                    events: 'SCAN',
                                    risk: 'critical',
                                    ts: Date.now()
                                });
                            });
                        }
                    }
                );
                
                // OPTIMIZACIÓN: Limitar búsqueda a archivos modificados recientemente
                exec(`find ${watchPath} -name "*.php" -mtime -1 -exec grep -l 'base64_decode' {} \\; 2>/dev/null | head -5`, 
                    { timeout: 8000 }, 
                    (err, stdout) => {
                        if (!err && stdout) {
                            const files = stdout.trim().split('\n').filter(f => f);
                            files.forEach(file => {
                                socket.emit('file_change', {
                                    detail: `Firma maliciosa detectada: base64_decode`,
                                    filePath: file,
                                    events: 'SCAN',
                                    risk: 'critical',
                                    ts: Date.now()
                                });
                            });
                        }
                    }
                );
            } catch (error) {
                console.error('❌ Error al escanear archivos:', error);
            }
        }, config.fileScanInterval);
    }

    // Monitoreo de crontab
    if (isLinux) {
        crontabInterval = setInterval(() => {
            try {
                // Verificar crontab de todos los usuarios
                exec("for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null | grep -v '^#' | grep -v '^$' && echo \"USER:$user\"; done", 
                    { timeout: 5000 }, 
                    (err, stdout) => {
                        const suspicious = [];
                        
                        if (!err && stdout && stdout.trim()) {
                            const lines = stdout.trim().split('\n').filter(l => l.trim());
                            let currentUser = '';
                            
                            lines.forEach(line => {
                                if (line.startsWith('USER:')) {
                                    currentUser = line.replace('USER:', '');
                                } else if (line.trim()) {
                                    // Detectar tareas sospechosas
                                    if (line.includes('curl') || line.includes('wget') || 
                                        line.includes('php') || line.includes('base64') ||
                                        line.includes('eval') || line.includes('sh -c')) {
                                        suspicious.push({
                                            user: currentUser,
                                            cron: line.trim()
                                        });
                                    }
                                }
                            });
                        }
                        
                        // Siempre enviar resultado, incluso si está vacío
                        socket.emit('crontab_alert', suspicious);
                    }
                );
            } catch (error) {
                // Enviar array vacío en caso de error
                socket.emit('crontab_alert', []);
            }
        }, config.crontabCheckInterval);
    }

    // Monitoreo de sitios web
    if (isLinux) {
        // Descubrir sitios al inicio
        discoverSites();
        
        // Monitorear sitios cada minuto
        siteCheckInterval = setInterval(() => {
            discoverSites();
            checkAllSites();
        }, config.siteCheckInterval);
    }

    // Monitor de archivos (solo Linux)
    if (isLinux) {
        const watchPath = process.env.WATCH_PATH || '/var/www/vhosts';
        
        // Verificar si inotifywait está instalado
        exec('which inotifywait', (err) => {
            if (err) {
                console.warn('⚠️ inotifywait no está instalado');
                console.log('💡 Instala con: apt-get install inotify-tools (Debian/Ubuntu) o yum install inotify-tools (RHEL/CentOS)');
                console.log('🔄 Usando método alternativo de monitoreo de archivos...');
                
                // Método alternativo: usar find con polling
                startFileWatcherAlternative(watchPath);
            } else {
                // Usar inotifywait si está disponible
                startInotifyWatcher(watchPath);
            }
        });
    } else {
        console.log('💡 Monitor de archivos disponible solo en Linux');
    }
}

// OPTIMIZACIÓN: Batching de eventos de archivos para reducir CPU
let fileEventBuffer = [];
let fileEventFlushTimer = null;
const FILE_EVENT_BATCH_SIZE = 10;
const FILE_EVENT_FLUSH_INTERVAL = 2000; // Flush cada 2 segundos

function flushFileEvents() {
    if (fileEventBuffer.length === 0) return;
    
    const eventsToSend = fileEventBuffer.splice(0, FILE_EVENT_BATCH_SIZE);
    eventsToSend.forEach(event => {
        socket.emit('file_change', event);
    });
    
    // Si quedan más eventos, programar otro flush
    if (fileEventBuffer.length > 0) {
        fileEventFlushTimer = setTimeout(flushFileEvents, FILE_EVENT_FLUSH_INTERVAL);
    } else {
        fileEventFlushTimer = null;
    }
}

function queueFileEvent(event) {
    fileEventBuffer.push(event);
    
    // Si el buffer está lleno o es el primer evento, iniciar flush
    if (fileEventBuffer.length >= FILE_EVENT_BATCH_SIZE || !fileEventFlushTimer) {
        if (fileEventFlushTimer) {
            clearTimeout(fileEventFlushTimer);
        }
        fileEventFlushTimer = setTimeout(flushFileEvents, 100); // Flush rápido si hay muchos eventos
    }
}

// Función para iniciar inotifywait (OPTIMIZADA)
function startInotifyWatcher(watchPath) {
    try {
        fileWatcher = spawn('inotifywait', ['-mr', '-e', 'modify,create,delete', '--format', '%w%f %e', watchPath], {
            stdio: ['ignore', 'pipe', 'pipe']
        });
        
        // OPTIMIZACIÓN: Procesar eventos en batch y reducir llamadas a exec
        let pendingEvents = new Map(); // Agrupar eventos por archivo
        let processCheckTimer = null;
        
        fileWatcher.stdout.on('data', (data) => {
            const lines = data.toString().trim().split('\n');
            lines.forEach(line => {
                if (!line.trim()) return;
                
                const parts = line.split(' ');
                if (parts.length < 2) return;
                
                const filePath = parts[0];
                const events = parts.slice(1).join(' ');
                
                // Filtrar archivos ignorados
                if (shouldIgnoreFile(filePath)) {
                    return;
                }
                
                // Agrupar eventos del mismo archivo (evitar duplicados)
                if (!pendingEvents.has(filePath)) {
                    pendingEvents.set(filePath, {
                        filePath: filePath,
                        events: events,
                        count: 0,
                        firstSeen: Date.now()
                    });
                }
                
                const eventData = pendingEvents.get(filePath);
                eventData.count++;
                eventData.events = events; // Actualizar eventos
                
                // CAPTURA RÁPIDA: Si es sospechoso, capturar inmediatamente
                if (shouldQuickCapture(filePath, events)) {
                    quickCaptureFile(filePath, events);
                }
            });
            
            // OPTIMIZACIÓN: Procesar eventos en batch cada 1 segundo (en lugar de inmediatamente)
            if (!processCheckTimer) {
                processCheckTimer = setTimeout(() => {
                    processCheckTimer = null;
                    processFileEventsBatch(pendingEvents);
                    pendingEvents.clear();
                }, 1000);
            }
        });
        
        fileWatcher.stderr.on('data', (data) => {
            const errorMsg = data.toString().trim();
            // Ignorar errores menores de inotifywait
            if (!errorMsg.includes('Couldn\'t watch') && !errorMsg.includes('No such file')) {
                console.warn('⚠️ inotifywait:', errorMsg);
            }
        });
        
        fileWatcher.on('error', (error) => {
            console.warn('⚠️ Error al iniciar inotifywait:', error.message);
            console.log('🔄 Cambiando a método alternativo...');
            startFileWatcherAlternative(watchPath);
        });
        
        console.log('✅ Monitor de archivos activo con inotifywait');
    } catch (error) {
        console.warn('⚠️ No se pudo iniciar inotifywait:', error.message);
        startFileWatcherAlternative(watchPath);
    }
}

// Método alternativo: usar find con polling
function startFileWatcherAlternative(watchPath) {
    let lastCheck = Date.now();
    const fileCheckInterval = setInterval(() => {
        exec(`find ${watchPath} -type f -newermt "@${Math.floor(lastCheck / 1000)}" 2>/dev/null | head -20`, 
            { timeout: 5000 }, 
            (err, stdout) => {
                if (!err && stdout) {
                    const files = stdout.trim().split('\n').filter(f => f);
                    files.forEach(filePath => {
                        // Filtrar archivos ignorados
                        if (shouldIgnoreFile(filePath)) {
                            return;
                        }
                        
                        const riskLevel = assessFileRisk(filePath, 'MODIFY');
                        
                        // CAPTURA RÁPIDA: Si es un archivo sospechoso en carpeta temp, capturarlo inmediatamente
                        if (shouldQuickCapture(filePath, 'MODIFY')) {
                            quickCaptureFile(filePath, 'MODIFY');
                        }
                        
                        // OPTIMIZACIÓN: Solo verificar proceso para archivos de alto riesgo
                        const shouldCheckProcess = riskLevel === 'high' || riskLevel === 'critical';
                        
                        if (shouldCheckProcess) {
                            exec(`lsof "${filePath}" 2>/dev/null | head -1`, { timeout: 1000 }, (err, stdout) => {
                                let processInfo = null;
                                
                                if (!err && stdout && stdout.trim()) {
                                    const parts = stdout.trim().split(/\s+/);
                                    if (parts.length >= 2) {
                                        processInfo = {
                                            command: parts[0],
                                            pid: parts[1],
                                            user: parts[2] || 'unknown'
                                        };
                                    }
                                }
                                
                                queueFileEvent({
                                    detail: `${filePath} MODIFY`,
                                    filePath: filePath,
                                    events: 'MODIFY',
                                    risk: riskLevel,
                                    process: processInfo,
                                    ts: Date.now()
                                });
                            });
                        } else {
                            // Para archivos de bajo riesgo, enviar sin verificar proceso
                            queueFileEvent({
                                detail: `${filePath} MODIFY`,
                                filePath: filePath,
                                events: 'MODIFY',
                                risk: riskLevel,
                                process: null,
                                ts: Date.now()
                            });
                        }
                    });
                }
                lastCheck = Date.now();
            }
        );
    }, getThrottledInterval(20000)); // OPTIMIZACIÓN: Verificar cada 20 segundos con throttling
    
    fileWatcher = { kill: () => clearInterval(fileCheckInterval) };
    console.log('✅ Monitor de archivos activo (método alternativo)');
}

// Verificar si un archivo debe ser capturado rápidamente
function shouldQuickCapture(filePath, events) {
    if (!filePath || !events) return false;
    
    const pathLower = filePath.toLowerCase();
    const eventsLower = events.toLowerCase();
    
    // Solo capturar archivos creados o modificados (no eliminados)
    if (eventsLower.includes('delete')) return false;
    
    // Verificar si está en una carpeta de monitoreo
    const watchFolders = config.quickCapture?.watchFolders || [];
    const isInWatchedFolder = watchFolders.some(folder => {
        if (folder.includes('**')) {
            // Patrón glob
            const pattern = folder.replace(/\*\*/g, '.*');
            return new RegExp(pattern).test(pathLower);
        }
        return pathLower.includes(folder.toLowerCase());
    });
    
    if (!isInWatchedFolder) return false;
    
    // Verificar extensión sospechosa
    const ext = path.extname(filePath).toLowerCase();
    const suspiciousExtensions = config.quickCapture?.suspiciousExtensions || ['.php', '.phtml', '.sh', '.exe'];
    if (!suspiciousExtensions.includes(ext)) return false;
    
    // Verificar nombre sospechoso
    const fileName = path.basename(filePath).toLowerCase();
    const suspiciousPatterns = config.quickCapture?.suspiciousPatterns || [];
    const hasSuspiciousName = suspiciousPatterns.some(pattern => {
        if (pattern instanceof RegExp) {
            return pattern.test(fileName) || pattern.test(pathLower);
        }
        return fileName.includes(pattern.toLowerCase()) || pathLower.includes(pattern.toLowerCase());
    });
    
    // También capturar si está en /tmp o /var/tmp con extensión sospechosa
    const isInTemp = pathLower.includes('/tmp/') || pathLower.includes('/var/tmp/') || pathLower.includes('/dev/shm/');
    
    return hasSuspiciousName || (isInTemp && suspiciousExtensions.includes(ext));
}

// Capturar archivo sospechoso rápidamente
function quickCaptureFile(filePath) {
    try {
        // Verificar que el archivo existe
        if (!fs.existsSync(filePath)) {
            return; // Ya fue eliminado, muy rápido
        }
        
        // Verificar tamaño máximo
        const stats = fs.statSync(filePath);
        const maxSize = config.quickCapture?.maxFileSize || (5 * 1024 * 1024);
        if (stats.size > maxSize) {
            console.log(`⚠️ Archivo demasiado grande para captura rápida: ${filePath} (${stats.size} bytes)`);
            return;
        }
        
        // Crear carpeta de captura si no existe
        const capturePath = config.quickCapture?.capturePath || '/var/sentinel/captured';
        if (!fs.existsSync(capturePath)) {
            fs.mkdirSync(capturePath, { recursive: true });
        }
        
        // Verificar tamaño de la carpeta antes de capturar
        const maxFolderSize = config.quickCapture?.maxFolderSize || (2 * 1024 * 1024 * 1024); // 2GB
        const currentFolderSize = getFolderSize(capturePath);
        
        if (currentFolderSize >= maxFolderSize) {
            // Limpiar archivos antiguos antes de capturar
            cleanupCaptureFolder(capturePath, maxFolderSize);
        }
        
        // Generar nombre único para el archivo capturado
        const fileName = path.basename(filePath);
        const timestamp = Date.now();
        const hash = Math.random().toString(36).substring(2, 9);
        const capturedFileName = `${timestamp}_${hash}_${fileName}`;
        const capturedPath = path.join(capturePath, capturedFileName);
        
        // Copiar archivo rápidamente
        fs.copyFileSync(filePath, capturedPath);
        
        // Cambiar permisos para que no sea ejecutable
        fs.chmodSync(capturedPath, 0o644);
        
        // Emitir evento al dashboard
        socket.emit('file_captured', {
            original: filePath,
            captured: capturedPath,
            fileName: capturedFileName,
            size: stats.size,
            timestamp: timestamp,
            reason: 'suspicious_file_in_temp'
        });
        
        console.log(`🚨 ARCHIVO SOSPECHOSO CAPTURADO: ${filePath} -> ${capturedPath}`);
    } catch (error) {
        console.error(`❌ Error al capturar archivo ${filePath}:`, error.message);
        // No emitir error al dashboard para no saturar, solo log
    }
}

// Verificar si un archivo debe ser ignorado
function shouldIgnoreFile(filePath) {
    if (!filePath) return true;
    
    const pathLower = filePath.toLowerCase();
    const ignoredFiles = config.ignoredFiles || [];
    
    for (const pattern of ignoredFiles) {
        const patternLower = pattern.toLowerCase();
        
        // Patrón exacto (incluye subcadenas)
        if (pathLower.includes(patternLower)) {
            return true;
        }
        
        // Patrón con wildcard (*)
        if (patternLower.includes('*')) {
            const regexPattern = patternLower
                .replace(/\./g, '\\.')
                .replace(/\*/g, '.*');
            const regex = new RegExp(regexPattern);
            if (regex.test(pathLower) || pathLower.endsWith(patternLower.replace('*', ''))) {
                return true;
            }
        }
        
        // Patrón de carpeta (termina con /)
        if (patternLower.endsWith('/') && pathLower.includes(patternLower)) {
            return true;
        }
        
        // Patrones específicos adicionales
        if (pathLower.includes('temp-write-test')) {
            return true; // Archivos temporales de WordPress
        }
        if (pathLower.includes('access_ssl_log') || pathLower.includes('proxy_access_log') || 
            pathLower.includes('error_log') || pathLower.includes('access_log')) {
            return true; // Logs del sistema
        }
    }
    
    return false;
}

// Evaluar riesgo de archivo según su ruta y tipo de evento
function assessFileRisk(filePath, events) {
    if (!filePath) return 'low';
    
    const path = filePath.toLowerCase();
    const eventStr = (events || '').toLowerCase();
    
    // CARPETAS CRÍTICAS - Máxima prioridad
    // /tmp y /var/tmp - donde el malware descarga ejecutables
    if (path.includes('/tmp/') || path.includes('/var/tmp/')) {
        if (path.endsWith('.php') || path.endsWith('.sh') || path.endsWith('.bin') || 
            path.endsWith('.exe') || !path.includes('.')) {
            return 'critical';
        }
        return 'high';
    }
    
    // wp-content/uploads - donde suben shells PHP
    if (path.includes('wp-content/uploads') && path.endsWith('.php')) {
        return 'critical';
    }
    
    // wp-includes - archivos críticos de WordPress
    if (path.includes('wp-includes')) {
        if (path.includes('pluggable.php') || path.includes('script-loader.php')) {
            return 'critical';
        }
        return 'high';
    }
    
    // Archivos críticos del sistema
    if (path.includes('/etc/') || path.includes('/bin/') || path.includes('/sbin/') || 
        path.includes('/usr/bin/') || path.includes('/usr/sbin/')) {
        return 'critical';
    }
    
    // ARCHIVOS CLAVE A VIGILAR
    // .htaccess - buscan redirigir tráfico
    if (path.includes('.htaccess')) {
        return 'critical';
    }
    
    // index.php - primer sitio donde inyectan código
    if (path.endsWith('index.php') || path.includes('/index.php')) {
        if (eventStr.includes('modify')) {
            return 'high';
        }
        return 'medium';
    }
    
    // wp-config.php - buscan credenciales
    if (path.includes('wp-config.php')) {
        return 'critical';
    }
    
    // Archivos PHP ejecutables (alto riesgo)
    if (path.endsWith('.php') || path.endsWith('.php5') || path.endsWith('.phtml')) {
        // Archivos ocultos sospechosos
        if (path.includes('.sys_lock') || path.includes('wp-vcd.php') || 
            path.includes('crypt.php') || path.includes('shell.php') ||
            path.includes('backdoor') || path.includes('c99')) {
            return 'critical';
        }
        
        if (eventStr.includes('create') || eventStr.includes('delete')) {
            return 'high';
        }
        return 'medium';
    }
    
    // Archivos de configuración
    if (path.endsWith('.conf') || path.endsWith('.config') || path.endsWith('.ini') || 
        path.includes('config')) {
        return 'high';
    }
    
    // Archivos ejecutables
    if (path.endsWith('.sh') || path.endsWith('.py') || path.endsWith('.pl') || 
        path.endsWith('.exe') || path.endsWith('.bin')) {
        return 'high';
    }
    
    // Eliminaciones siempre son de alto riesgo
    if (eventStr.includes('delete')) {
        return 'high';
    }
    
    // Creaciones en directorios sensibles
    if (eventStr.includes('create') && 
        (path.includes('www') || path.includes('public') || path.includes('html') ||
         path.includes('vhosts'))) {
        return 'medium';
    }
    
    return 'low';
}

// Descubrir sitios web en /var/www/vhosts/
function discoverSites() {
    try {
        const vhostsPath = config.vhostsPath;
        
        if (!fs.existsSync(vhostsPath)) {
            console.warn(`⚠️ Ruta de vhosts no encontrada: ${vhostsPath}`);
            return;
        }
        
        const dirs = fs.readdirSync(vhostsPath, { withFileTypes: true });
        
        dirs.forEach(dirent => {
            if (dirent.isDirectory()) {
                const domain = dirent.name;
                
                // Ignorar directorios del sistema
                if (domain.startsWith('.') || domain === 'system' || domain === 'default') {
                    return;
                }
                
                // Verificar si existe httpdocs o public_html
                const httpdocsPath = `${vhostsPath}/${domain}/httpdocs`;
                const publicHtmlPath = `${vhostsPath}/${domain}/public_html`;
                
                if (fs.existsSync(httpdocsPath) || fs.existsSync(publicHtmlPath)) {
                    // Construir URL (asumir HTTP por defecto, se probará HTTPS también)
                    if (!discoveredSites.has(domain)) {
                        discoveredSites.set(domain, {
                            domain: domain,
                            url: `http://${domain}`,
                            status: 'unknown',
                            lastCheck: null,
                            responseTime: null,
                            statusCode: null,
                            error: null
                        });
                        console.log(`🌐 Sitio descubierto: ${domain}`);
                    }
                }
            }
        });
    } catch (error) {
        console.error('❌ Error al descubrir sitios:', error);
    }
}

// Verificar estado de un sitio web
function checkSite(site) {
    return new Promise((resolve) => {
        const url = new URL(site.url);
        const isHttps = url.protocol === 'https:';
        const client = isHttps ? https : http;
        
        const options = {
            hostname: url.hostname,
            port: url.port || (isHttps ? 443 : 80),
            path: url.pathname || '/',
            method: 'GET',
            timeout: 10000,
            headers: {
                'User-Agent': 'Sentinel-Monitor/1.0'
            },
            rejectUnauthorized: false // Permitir certificados autofirmados
        };
        
        const startTime = Date.now();
        
        const req = client.request(options, (res) => {
            const responseTime = Date.now() - startTime;
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                const statusCode = res.statusCode;
                let status = 'active';
                let error = null;
                
                if (statusCode >= 200 && statusCode < 400) {
                    status = 'active';
                } else if (statusCode >= 400 && statusCode < 500) {
                    status = 'error';
                    error = `Error ${statusCode}`;
                } else if (statusCode >= 500) {
                    status = 'down';
                    error = `Error del servidor ${statusCode}`;
                }
                
                resolve({
                    ...site,
                    status,
                    statusCode,
                    responseTime,
                    error,
                    lastCheck: Date.now()
                });
            });
        });
        
        req.on('error', (err) => {
            const responseTime = Date.now() - startTime;
            
            // Si falla HTTP, intentar HTTPS
            if (!isHttps && !site.triedHttps) {
                site.triedHttps = true;
                site.url = site.url.replace('http://', 'https://');
                checkSite(site).then(resolve);
                return;
            }
            
            resolve({
                ...site,
                status: 'down',
                statusCode: null,
                responseTime,
                error: err.message,
                lastCheck: Date.now()
            });
        });
        
        req.on('timeout', () => {
            req.destroy();
            resolve({
                ...site,
                status: 'down',
                statusCode: null,
                responseTime: 10000,
                error: 'Timeout',
                lastCheck: Date.now()
            });
        });
        
        req.end();
    });
}

// Verificar todos los sitios descubiertos
async function checkAllSites() {
    if (discoveredSites.size === 0) {
        return;
    }
    
    const sites = Array.from(discoveredSites.values());
    const results = [];
    
    // Verificar sitios en paralelo (máximo 5 a la vez para no sobrecargar)
    const batchSize = 5;
    for (let i = 0; i < sites.length; i += batchSize) {
        const batch = sites.slice(i, i + batchSize);
        const batchResults = await Promise.all(batch.map(site => checkSite(site)));
        results.push(...batchResults);
    }
    
    // Actualizar cache y detectar cambios de estado
    const changedSites = [];
    const downSites = [];
    const errorSites = [];
    
    results.forEach(result => {
        const previousStatus = siteStatusHistory.get(result.domain);
        const currentStatus = result.status;
        
        // Solo notificar si el estado cambió
        if (previousStatus && previousStatus !== currentStatus) {
            changedSites.push({
                ...result,
                previousStatus: previousStatus,
                statusChanged: true
            });
            
            if (currentStatus === 'down') {
                downSites.push(result);
            } else if (currentStatus === 'error') {
                errorSites.push(result);
            }
        }
        
        // Actualizar historial
        siteStatusHistory.set(result.domain, currentStatus);
        discoveredSites.set(result.domain, result);
    });
    
    // Enviar estado de todos los sitios
    socket.emit('sites_status', results);
    
    // Solo enviar alertas si hay cambios de estado
    if (changedSites.length > 0) {
        socket.emit('sites_alert', {
            changed: changedSites,
            down: downSites,
            errors: errorSites,
            timestamp: Date.now()
        });
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
    if (processInterval) {
        clearInterval(processInterval);
        processInterval = null;
    }
    if (fileScanInterval) {
        clearInterval(fileScanInterval);
        fileScanInterval = null;
    }
    if (crontabInterval) {
        clearInterval(crontabInterval);
        crontabInterval = null;
    }
    if (siteCheckInterval) {
        clearInterval(siteCheckInterval);
        siteCheckInterval = null;
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
