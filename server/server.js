const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { verifyToken, JWT_SECRET } = require('./authMiddleware');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Serve static files from the client directory
app.use(express.json());
app.use(express.static(path.join(__dirname, '../client')));

// Persistent user store
const USERS_FILE = path.join(__dirname, 'users.json');

const loadUsers = () => {
    try {
        if (!fs.existsSync(USERS_FILE)) {
            fs.writeFileSync(USERS_FILE, JSON.stringify([]));
            return [];
        }
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error("Error loading users:", err);
        return [];
    }
};

const saveUsers = (users) => {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (err) {
        console.error("Error saving users:", err);
    }
};

let users_db = loadUsers();

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (users_db.find(u => u.username === username)) {
            return res.status(400).json({ message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        users_db.push({ username, password: hashedPassword });
        saveUsers(users_db);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Error registering user' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        let user = users_db.find(u => u.username === username);
        
        // AUTO-REGISTRATION: If user doesn't exist, create them
        if (!user) {
            console.log(`[AUTO-REGISTER] New user: ${username}`);
            const hashedPassword = await bcrypt.hash(password || 'password123', 10);
            user = { username, password: hashedPassword };
            users_db.push(user);
            saveUsers(users_db);
        } else {
            console.log(`[AUTO-LOGIN] Existing user: ${username}`);
            // In this "Easy Access" mode, we allow the user in even if password doesn't match
            // as per user request ("yaru name potu login panalu login aganu")
        }
        
        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username: user.username });
    } catch (err) {
        console.error("Login exception:", err);
        res.status(500).json({ message: 'Error logging in' });
    }
});

// Basic signaling for WebRTC and Screenshot events
const users = {}; // Map socket.id to usernames or room info

// Socket.io Middleware for JWT authentication
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    const decoded = verifyToken(token);
    if (decoded) {
        socket.username = decoded.username;
        next();
    } else {
        next(new Error('Authentication error'));
    }
});

io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id} (Authenticated as: ${socket.username})`);
    
    // User joins a room
    socket.on('join_room', (roomId) => {
        const username = socket.username; // Use verified username from token
        socket.join(roomId);
        users[socket.id] = { roomId, username };
        console.log(`${username} (${socket.id}) joined room: ${roomId}`);
        
        // Notify others in the room
        socket.to(roomId).emit('user_joined', { id: socket.id, username });
        
        // Send list of existing users in room to the new user
        const clientsInRoom = io.sockets.adapter.rooms.get(roomId);
        if (clientsInRoom) {
            const usersInRoom = [...clientsInRoom].filter(id => id !== socket.id).map(id => ({
                id,
                username: users[id]?.username
            }));
            socket.emit('room_users', usersInRoom);
        }
    });

    // WebRTC Signaling
    socket.on('offer', (data) => {
        socket.to(data.target).emit('offer', {
            sdp: data.sdp,
            callerId: socket.id,
            callerName: users[socket.id]?.username
        });
    });

    socket.on('answer', (data) => {
        socket.to(data.target).emit('answer', {
            sdp: data.sdp,
            answererId: socket.id
        });
    });

    socket.on('ice_candidate', (data) => {
        socket.to(data.target).emit('ice_candidate', {
            candidate: data.candidate,
            senderId: socket.id
        });
    });

    // Screenshot Events
    socket.on('screenshot_attempt', (data) => {
        const user = users[socket.id];
        if (user) {
            console.log(`[ALERT] Screenshot attempt by ${user.username} in room ${user.roomId}`);
            // Log timestamp
            const time = new Date().toLocaleTimeString();
            console.log(`Log: User ${user.username} attempted screenshot at ${time}`);
            
            // Broadcast to others in the room
            socket.to(user.roomId).emit('screenshot_requested', {
                requesterId: socket.id,
                requesterName: user.username,
                time: time
            });
        }
    });

    socket.on('screenshot_response', (data) => {
        const user = users[socket.id];
        if (user) {
            // data.requesterId is the person who attempted
            // data.allowed is true/false
            console.log(`[RESPONSE] Screenshot by ${data.requesterId} was ${data.allowed ? 'allowed' : 'denied'} by ${user.username}`);
            io.to(data.requesterId).emit('screenshot_decision', {
                responderId: socket.id,
                responderName: user.username,
                allowed: data.allowed
            });
        }
    });
    
    socket.on('leave_room', () => {
        const user = users[socket.id];
        if (user) {
            console.log(`${user.username} left room: ${user.roomId}`);
            socket.to(user.roomId).emit('user_left', { id: socket.id, username: user.username });
            socket.leave(user.roomId);
            delete users[socket.id];
        }
    });

    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);
        const user = users[socket.id];
        if (user) {
            socket.to(user.roomId).emit('user_left', { id: socket.id, username: user.username });
            delete users[socket.id];
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
