const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

io.on('connection', (socket) => {
    socket.on('health_stats', (data) => io.emit('ui_health', data));
    socket.on('network_alert', (data) => io.emit('ui_network', data));
    socket.on('file_change', (data) => io.emit('ui_file', data));
    socket.on('panic_action', () => io.emit('trigger_panic'));
});

server.listen(4000, '0.0.0.0', () => console.log('âœ… Dashboard en puerto 4000'));
