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
    
    // Configuración de Socket.IO
    socketIO: {
        cors: {
            origin: false, // Sin CORS, solo localhost
            credentials: false
        },
        transports: ['websocket', 'polling']
    }
};
