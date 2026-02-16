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
        defaultModel: process.env.AI_MODEL || 'mistral' // mistral es excelente para análisis de seguridad
    },
    
    // Configuración de logs persistentes
    logBufferSize: {
        network: 200,    // Últimas 200 conexiones de red
        files: 200,      // Últimos 200 cambios de archivos
        processes: 100,  // Últimos 100 procesos sospechosos
        crontab: 50      // Últimas 50 tareas de crontab
    },
    
    // Configuración de autenticación
    auth: {
        password: process.env.ADMIN_PASSWORD || 'H@wkins22',
        sessionSecret: process.env.SESSION_SECRET || 'sentinel-secret-key-change-in-production'
    },
    
    // Configuración de Automatización SOC
    soc: {
        // Investigar automáticamente cada X logs sospechosos acumulados
        investigationThreshold: 10, // Investigar cada 10 logs sospechosos
        investigationInterval: 300000, // Verificar cada 5 minutos
        quarantinePath: process.env.QUARANTINE_PATH || '/var/sentinel/quarantine',
        reportsPath: process.env.REPORTS_PATH || '/var/sentinel/reports'
    }
};
