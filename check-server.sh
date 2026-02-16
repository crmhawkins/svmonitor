#!/bin/bash
# Script de verificación del servidor Sentinel

echo "🔍 Verificando servidor Sentinel..."
echo ""

# Verificar si el proceso está ejecutándose
if pgrep -f "dashboard/server.js" > /dev/null; then
    echo "✅ Proceso Node.js encontrado"
    ps aux | grep "dashboard/server.js" | grep -v grep
else
    echo "❌ Proceso Node.js NO está ejecutándose"
    echo "💡 Ejecuta: npm start"
fi

echo ""
echo "🔍 Verificando puerto 3813..."
if netstat -tuln | grep ":3813" > /dev/null || ss -tuln | grep ":3813" > /dev/null; then
    echo "✅ Puerto 3813 está en uso"
    netstat -tuln | grep ":3813" || ss -tuln | grep ":3813"
else
    echo "❌ Puerto 3813 NO está en uso"
fi

echo ""
echo "🔍 Probando conexión local..."
if curl -s http://127.0.0.1:3813 > /dev/null; then
    echo "✅ Servidor responde en http://127.0.0.1:3813"
else
    echo "❌ Servidor NO responde en http://127.0.0.1:3813"
    echo "💡 Verifica que el servidor esté ejecutándose"
fi

echo ""
echo "🔍 Verificando logs recientes..."
if [ -f "server.log" ]; then
    echo "Últimas líneas del log:"
    tail -5 server.log
else
    echo "No se encontró archivo de log"
fi
