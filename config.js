// Configuración del sistema Sentinel
module.exports = {
    // Puerto interno del dashboard (nginx redirige el 80 a este puerto)
    dashboardPort: process.env.DASHBOARD_PORT || 3813,
    
    // Puerto alternativo si el 3813 no está disponible
    dashboardPortFallback: process.env.DASHBOARD_PORT_FALLBACK || 8080,
    
    // Host - solo localhost para comunicaciones internas
    host: '127.0.0.1', // No usar 0.0.0.0 para seguridad
    
    // URL del dashboard para el agente (siempre localhost)
    // Se construye dinámicamente usando el puerto configurado
    getDashboardUrl: function() {
        const port = process.env.DASHBOARD_PORT || this.dashboardPort;
        return `http://127.0.0.1:${port}`;
    },
    
    // Intervalos de monitoreo (en ms)
    healthCheckInterval: 3000,
    networkCheckInterval: 2000,
    processCheckInterval: 5000,
    fileScanInterval: 30000, // Escaneo de firmas cada 30 segundos
    crontabCheckInterval: 60000, // Crontab cada minuto
    siteCheckInterval: 60000, // Monitoreo de sitios cada minuto
    
    // Ruta de sitios web (Plesk)
    vhostsPath: process.env.VHOSTS_PATH || '/var/www/vhosts',
    
    // Procesos a excluir del monitoreo (backend/frontend propios)
    excludedProcesses: process.env.EXCLUDED_PROCESSES ? 
        process.env.EXCLUDED_PROCESSES.split(',') : 
        ['dashboard/server.js', 'agent/agent.js', 'node dashboard', 'node agent'],
    
    // Archivos y patrones a ignorar en el monitoreo de archivos
    ignoredFiles: process.env.IGNORED_FILES ?
        process.env.IGNORED_FILES.split(',') :
        [
            'all_strings.txt',
            '*.log',
            '*.tmp',
            '*.cache',
            '*.swp',
            '*.swo',
            '.git/',
            'node_modules/',
            '.pm2/'
        ],
    
    // Configuración de Socket.IO
    socketIO: {
        cors: {
            origin: false, // Sin CORS, solo localhost
            credentials: false
        },
        transports: ['websocket', 'polling']
    },
    
    // Configuración de IA
    aiApi: {
        url: process.env.AI_API_URL || 'https://aiapi.hawkins.es/chat/chat',
        apiKey: process.env.AI_API_KEY || 'OllamaAPI_2024_K8mN9pQ2rS5tU7vW3xY6zA1bC4eF8hJ0lM',
        defaultModel: process.env.AI_MODEL || 'mistral:7b-instruct', // mistral:7b-instruct es excelente para análisis de seguridad
        // Modelos alternativos si mistral:7b-instruct no está disponible:
        // 'mistral', 'llama2', 'codellama', 'deepseek-coder', 'qwen2.5:7b'
        fallbackModel: process.env.AI_FALLBACK_MODEL || 'mistral'
    },
    
    // Configuración de logs persistentes (OPTIMIZADO: reducido para ahorrar RAM)
    logBufferSize: {
        network: 100,    // Últimas 100 conexiones de red (reducido de 200)
        files: 100,      // Últimos 100 cambios de archivos (reducido de 200)
        processes: 50,   // Últimos 50 procesos sospechosos (reducido de 100)
        crontab: 30      // Últimas 30 tareas de crontab (reducido de 50)
    },
    
    // Configuración de autenticación
    auth: {
        username: process.env.ADMIN_USERNAME || 'admin',
        password: process.env.ADMIN_PASSWORD || 'H@wkins22',
        sessionSecret: process.env.SESSION_SECRET || 'sentinel-secret-key-change-in-production',
        maxLoginAttempts: 5, // Intentos máximos antes de bloquear
        lockoutDuration: 15 * 60 * 1000 // 15 minutos en milisegundos
    },
    
    // Configuración de Automatización SOC
    soc: {
        // Investigar automáticamente cada X logs sospechosos acumulados
        investigationThreshold: 10, // Investigar cada 10 logs sospechosos
        investigationInterval: 300000, // Verificar cada 5 minutos
        quarantinePath: process.env.QUARANTINE_PATH || '/var/sentinel/quarantine',
        reportsPath: process.env.REPORTS_PATH || '/var/sentinel/reports',
        // Límite de tamaño para carpetas (2GB por defecto)
        maxFolderSize: 2 * 1024 * 1024 * 1024, // 2GB en bytes
        // Porcentaje de espacio a liberar cuando se alcanza el límite (20%)
        cleanupPercentage: 0.2
    },
    
    // Configuración de captura rápida de archivos sospechosos
    quickCapture: {
        // Carpetas a monitorear para captura rápida
        watchFolders: [
            '/tmp',
            '/var/tmp',
            '**/wp-content/uploads/**',
            '**/wp-content/cache/**',
            '**/wp-content/temp/**',
            '**/wp-content/upgrade/**',
            '/dev/shm'
        ],
        // Patrones de nombres sospechosos
        suspiciousPatterns: [
            /shell/i,
            /backdoor/i,
            /c99/i,
            /cpanel/i,
            /phpshell/i,
            /r57/i,
            /wso/i,
            /b374k/i,
            /\.php\.(jpg|png|gif|txt)$/i, // PHP disfrazado
            /^\.(htaccess|htpasswd|user\.ini)$/i,
            /^[a-f0-9]{32}\.php$/i, // Hash MD5 como nombre
            /^[a-f0-9]{40}\.php$/i, // Hash SHA1 como nombre
            /^[a-f0-9]{64}\.php$/i, // Hash SHA256 como nombre
            /^[0-9]+\.php$/i, // Solo números
            /^[a-z]{1,3}\.php$/i, // Nombres muy cortos
            /eval|base64|gzinflate|str_rot13/i // Contenido sospechoso en nombre
        ],
        // Extensions sospechosas en temp
        suspiciousExtensions: ['.php', '.phtml', '.php3', '.php4', '.php5', '.phps', '.sh', '.pl', '.py', '.exe', '.bin'],
        // Ruta donde guardar archivos capturados
        capturePath: process.env.CAPTURE_PATH || '/var/sentinel/captured',
        // Tamaño máximo de archivo a capturar (en bytes, 5MB)
        maxFileSize: 5 * 1024 * 1024,
        // Límite de tamaño para carpeta de capturas (2GB)
        maxFolderSize: 2 * 1024 * 1024 * 1024, // 2GB en bytes
        // Porcentaje de espacio a liberar cuando se alcanza el límite (20%)
        cleanupPercentage: 0.2
    },
    
    // Configuración de monitoreo de espacio en disco
    diskMonitoring: {
        // Intervalo de verificación de espacio (cada 2 minutos - más agresivo)
        checkInterval: 2 * 60 * 1000,
        // Umbral de alerta: porcentaje de uso del disco
        alertThreshold: 75, // Alerta cuando el disco esté al 75% (750GB de 1TB)
        // Umbral crítico: porcentaje de uso del disco
        criticalThreshold: 90, // Crítico cuando el disco esté al 90%
        // Umbral de crecimiento rápido: MB por hora
        rapidGrowthThreshold: 500, // Alerta si crece más de 500MB por hora
        // Rutas a monitorear
        monitoredPaths: [
            process.env.QUARANTINE_PATH || '/var/sentinel/quarantine',
            process.env.REPORTS_PATH || '/var/sentinel/reports',
            process.env.CAPTURE_PATH || '/var/sentinel/captured'
        ]
    },
    
    // Configuración de correo electrónico
    email: {
        enabled: process.env.EMAIL_ENABLED === 'true' || false,
        smtp: {
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: process.env.SMTP_SECURE === 'true' || false, // true para 465, false para otros
            auth: {
                user: process.env.SMTP_USER || '',
                pass: process.env.SMTP_PASS || ''
            }
        },
        from: process.env.EMAIL_FROM || 'sentinel@herasoft.ai',
        to: process.env.EMAIL_TO ? process.env.EMAIL_TO.split(',') : ['admin@herasoft.ai'],
        // Alertas que activan envío de correo
        alerts: {
            criticalActivity: true,      // Actividad extremadamente sospechosa
            massDowntime: true,          // Caída generalizada de sitios
            diskSpace: true,             // Espacio en disco bajo
            rapidGrowth: true             // Crecimiento rápido de archivos
        }
    }
};
