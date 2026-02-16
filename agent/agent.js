const { exec, spawn } = require('child_process');
const http = require('http');
const https = require('https');
const io = require('socket.io-client');
const os = require('os');
const fs = require('fs');
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
    networkInterval = setInterval(() => {
        try {
            if (isLinux) {
                // Detectar conexiones salientes desde PHP hacia puertos sospechosos (80, 443, 25)
                exec("ss -antp 2>/dev/null | grep -E 'php.*:443|php.*:80|php.*:25' | grep -E 'ESTAB|SYN-SENT'", 
                    { timeout: 2000 }, 
                    (err, stdout) => {
                        if (!err && stdout) {
                            socket.emit('network_alert', stdout);
                        }
                    }
                );
                
                // También detectar cualquier conexión PHP persistente
                exec("ss -antp 2>/dev/null | grep php | grep ESTAB", 
                    { timeout: 2000 }, 
                    (err, stdout) => {
                        if (!err && stdout) {
                            const lines = stdout.split('\n').filter(l => l.trim());
                            // Filtrar solo conexiones externas (no localhost)
                            const external = lines.filter(line => 
                                !line.includes('127.0.0.1') && 
                                !line.includes('::1') &&
                                (line.includes(':443') || line.includes(':80') || line.includes(':25'))
                            );
                            if (external.length > 0) {
                                socket.emit('network_alert', external.join('\n'));
                            }
                        }
                    }
                );
            } else {
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
            }
        } catch (error) {
            console.error('❌ Error al verificar red:', error);
        }
    }, config.networkCheckInterval);

    // Monitoreo de procesos PHP sospechosos
    if (isLinux) {
        processInterval = setInterval(() => {
            try {
                // Buscar procesos PHP que llevan mucho tiempo activos (posibles zombies)
                exec("ps aux | grep '[p]hp' | awk '{print $2, $3, $4, $9, $10, $11, $12, $13, $14, $15, $16, $17}'", 
                    { timeout: 2000 }, 
                    (err, stdout) => {
                        if (!err && stdout) {
                            const processes = [];
                            const lines = stdout.trim().split('\n').filter(l => l.trim());
                            
                            lines.forEach(line => {
                                const parts = line.trim().split(/\s+/);
                                if (parts.length >= 11) {
                                    const pid = parts[0];
                                    const cpu = parseFloat(parts[1]) || 0;
                                    const mem = parseFloat(parts[2]) || 0;
                                    const time = parts[3]; // Tiempo de ejecución
                                    const command = parts.slice(10).join(' ');
                                    
                                    // Detectar procesos sospechosos
                                    let suspicious = false;
                                    let reason = '';
                                    
                                    // CPU alta constante
                                    if (cpu > 20) {
                                        suspicious = true;
                                        reason = `CPU alto: ${cpu}%`;
                                    }
                                    
                                    // Tiempo de ejecución largo (más de 1 hora)
                                    if (time && time.includes(':')) {
                                        const [hours, mins] = time.split(':').map(Number);
                                        if (hours > 0 || (hours === 0 && mins > 30)) {
                                            suspicious = true;
                                            reason = reason ? `${reason}, Tiempo: ${time}` : `Tiempo largo: ${time}`;
                                        }
                                    }
                                    
                                    // Comandos sospechosos
                                    if (command.includes('base64') || command.includes('eval') || 
                                        command.includes('system') || command.includes('exec')) {
                                        suspicious = true;
                                        reason = reason ? `${reason}, Comando sospechoso` : 'Comando sospechoso';
                                    }
                                    
                                    if (suspicious) {
                                        processes.push({
                                            pid,
                                            cpu,
                                            mem,
                                            time,
                                            command,
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
            } catch (error) {
                console.error('❌ Error al verificar procesos:', error);
            }
        }, config.processCheckInterval);
    }

    // Escaneo periódico de firmas maliciosas en archivos PHP
    if (isLinux) {
        fileScanInterval = setInterval(() => {
            try {
                const watchPath = process.env.WATCH_PATH || '/var/www/vhosts';
                
                // Buscar eval( y base64_decode en archivos PHP
                exec(`grep -rnl 'eval(' ${watchPath} --include="*.php" 2>/dev/null | head -10`, 
                    { timeout: 10000 }, 
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
                
                exec(`grep -rnl 'base64_decode' ${watchPath} --include="*.php" 2>/dev/null | head -10`, 
                    { timeout: 10000 }, 
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
                        if (!err && stdout) {
                            const lines = stdout.trim().split('\n').filter(l => l.trim());
                            const suspicious = [];
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
                            
                            if (suspicious.length > 0) {
                                socket.emit('crontab_alert', suspicious);
                            }
                        }
                    }
                );
            } catch (error) {
                // Ignorar errores de usuarios sin crontab
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

// Función para iniciar inotifywait
function startInotifyWatcher(watchPath) {
    try {
        fileWatcher = spawn('inotifywait', ['-mr', '-e', 'modify,create,delete', '--format', '%w%f %e', watchPath], {
            stdio: ['ignore', 'pipe', 'pipe']
        });
        
        fileWatcher.stdout.on('data', (data) => {
            const lines = data.toString().trim().split('\n');
            lines.forEach(line => {
                if (line.trim()) {
                    const [filePath, events] = line.split(' ');
                    const riskLevel = assessFileRisk(filePath, events);
                    
                    socket.emit('file_change', { 
                        detail: line.trim(),
                        filePath: filePath,
                        events: events,
                        risk: riskLevel,
                        ts: Date.now() 
                    });
                }
            });
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
                        const riskLevel = assessFileRisk(filePath, 'MODIFY');
                        socket.emit('file_change', {
                            detail: `${filePath} MODIFY`,
                            filePath: filePath,
                            events: 'MODIFY',
                            risk: riskLevel,
                            ts: Date.now()
                        });
                    });
                }
                lastCheck = Date.now();
            }
        );
    }, 5000); // Verificar cada 5 segundos
    
    fileWatcher = { kill: () => clearInterval(fileCheckInterval) };
    console.log('✅ Monitor de archivos activo (método alternativo)');
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
    
    // Actualizar cache y enviar resultados
    results.forEach(result => {
        discoveredSites.set(result.domain, result);
    });
    
    // Enviar estado de todos los sitios
    socket.emit('sites_status', results);
    
    // Enviar alertas si hay sitios caídos o con errores
    const downSites = results.filter(s => s.status === 'down');
    const errorSites = results.filter(s => s.status === 'error');
    
    if (downSites.length > 0 || errorSites.length > 0) {
        socket.emit('sites_alert', {
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
