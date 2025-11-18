/**
 * SheCab Backend Server (Node.js + Express)
 * Simple backend to connect with the HTML frontend
 * 
 * Installation:
 * npm init -y
 * npm install express cors jsonwebtoken bcrypt sqlite3 multer
 * 
 * Run:
 * node server.js
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3001;
const SECRET_KEY = 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve frontend files

// File upload configuration
const upload = multer({ 
    dest: 'uploads/',
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Initialize SQLite Database
const db = new sqlite3.Database('./shecab.db', (err) => {
    if (err) console.error('Database error:', err);
    else console.log('✅ Connected to SQLite database');
});

// Create tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        emergency_contact TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Rides table
    db.run(`CREATE TABLE IF NOT EXISTS rides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rider_id INTEGER NOT NULL,
        driver_id INTEGER,
        pickup TEXT NOT NULL,
        dropoff TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        started_at DATETIME,
        completed_at DATETIME,
        FOREIGN KEY (rider_id) REFERENCES users(id),
        FOREIGN KEY (driver_id) REFERENCES users(id)
    )`);

    // SOS Events table
    db.run(`CREATE TABLE IF NOT EXISTS sos_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ride_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        confidence REAL NOT NULL,
        face_count INTEGER,
        emotions TEXT,
        status TEXT DEFAULT 'active',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Telemetry frames (optional - for storing emotion data)
    db.run(`CREATE TABLE IF NOT EXISTS telemetry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ride_id INTEGER,
        face_count INTEGER,
        emotions TEXT,
        distress_score REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    console.log('✅ Database tables created');
});

// ==============================================
// AUTHENTICATION MIDDLEWARE
// ==============================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// ==============================================
// API ROUTES
// ==============================================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Register
app.post('/api/auth/register', async (req, res) => {
    const { name, phone, email, password, role, emergency_contact } = req.body;

    if (!name || !phone || !email || !password || !role) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        // Hash password
        const password_hash = await bcrypt.hash(password, 10);

        // Insert user
        db.run(
            `INSERT INTO users (name, phone, email, password_hash, role, emergency_contact) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [name, phone, email, password_hash, role, emergency_contact],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Phone or email already registered' });
                    }
                    return res.status(500).json({ error: 'Registration failed' });
                }

                // Generate token
                const token = jwt.sign(
                    { id: this.lastID, phone, role },
                    SECRET_KEY,
                    { expiresIn: '24h' }
                );

                res.json({
                    token,
                    user: { id: this.lastID, name, phone, email, role }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { phone, password } = req.body;

    db.get('SELECT * FROM users WHERE phone = ?', [phone], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign(
            { id: user.id, phone: user.phone, role: user.role },
            SECRET_KEY,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                phone: user.phone,
                email: user.email,
                role: user.role
            }
        });
    });
});

// Get current user
app.get('/api/users/me', authenticateToken, (req, res) => {
    db.get('SELECT id, name, phone, email, role, emergency_contact FROM users WHERE id = ?', 
        [req.user.id], 
        (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json(user);
        }
    );
});

// Create ride
app.post('/api/rides', authenticateToken, (req, res) => {
    const { pickup, dropoff, driver_id } = req.body;

    db.run(
        `INSERT INTO rides (rider_id, driver_id, pickup, dropoff, status) 
         VALUES (?, ?, ?, ?, 'pending')`,
        [req.user.id, driver_id || null, pickup, dropoff],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to create ride' });
            }

            db.get('SELECT * FROM rides WHERE id = ?', [this.lastID], (err, ride) => {
                res.json(ride);
            });
        }
    );
});

// Get all rides
app.get('/api/rides', authenticateToken, (req, res) => {
    let query = 'SELECT * FROM rides';
    let params = [];

    // Filter by role
    if (req.user.role === 'rider') {
        query += ' WHERE rider_id = ?';
        params.push(req.user.id);
    } else if (req.user.role === 'driver') {
        query += ' WHERE driver_id = ?';
        params.push(req.user.id);
    }

    query += ' ORDER BY created_at DESC';

    db.all(query, params, (err, rides) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch rides' });
        }
        res.json(rides);
    });
});

// Get single ride
app.get('/api/rides/:id', authenticateToken, (req, res) => {
    db.get('SELECT * FROM rides WHERE id = ?', [req.params.id], (err, ride) => {
        if (err || !ride) {
            return res.status(404).json({ error: 'Ride not found' });
        }
        res.json(ride);
    });
});

// Update ride
app.patch('/api/rides/:id', authenticateToken, (req, res) => {
    const { status } = req.body;
    const updates = [];
    const params = [];

    if (status) {
        updates.push('status = ?');
        params.push(status);

        if (status === 'active') {
            updates.push('started_at = ?');
            params.push(new Date().toISOString());
        } else if (status === 'completed') {
            updates.push('completed_at = ?');
            params.push(new Date().toISOString());
        }
    }

    params.push(req.params.id);

    db.run(
        `UPDATE rides SET ${updates.join(', ')} WHERE id = ?`,
        params,
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to update ride' });
            }

            db.get('SELECT * FROM rides WHERE id = ?', [req.params.id], (err, ride) => {
                res.json(ride);
            });
        }
    );
});

// Upload frame for emotion detection
app.post('/api/telemetry/frame', authenticateToken, upload.single('frame'), (req, res) => {
    // In production, process the image with OpenCV/TensorFlow here
    // For now, return mock data
    
    const mockResult = {
        processed: true,
        faceCount: Math.floor(Math.random() * 3),
        emotions: {
            happy: Math.random(),
            neutral: Math.random(),
            sad: Math.random(),
            angry: Math.random(),
            fear: Math.random()
        },
        distressDetected: Math.random() > 0.9,
        timestamp: new Date().toISOString()
    };

    // Store telemetry
    db.run(
        `INSERT INTO telemetry (ride_id, face_count, emotions, distress_score) 
         VALUES (?, ?, ?, ?)`,
        [req.body.ride_id || null, mockResult.faceCount, JSON.stringify(mockResult.emotions), 0.5],
        (err) => {
            if (err) console.error('Telemetry error:', err);
        }
    );

    // Clean up uploaded file
    if (req.file) {
        fs.unlink(req.file.path, (err) => {
            if (err) console.error('File cleanup error:', err);
        });
    }

    res.json(mockResult);
});

// Create SOS event
app.post('/api/sos', authenticateToken, (req, res) => {
    const { ride_id, reason, confidence, face_count, emotions } = req.body;

    db.run(
        `INSERT INTO sos_events (ride_id, reason, confidence, face_count, emotions, status) 
         VALUES (?, ?, ?, ?, ?, 'active')`,
        [ride_id, reason, confidence, face_count, JSON.stringify(emotions)],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to create SOS event' });
            }

            // Update ride status to emergency
            db.run('UPDATE rides SET status = ? WHERE id = ?', ['emergency', ride_id]);

            // Send notifications (implement with Twilio/SendGrid)
            sendSOSNotifications(ride_id, this.lastID);

            db.get('SELECT * FROM sos_events WHERE id = ?', [this.lastID], (err, sos) => {
                res.json(sos);
            });
        }
    );
});

// Get SOS events
app.get('/api/sos', authenticateToken, (req, res) => {
    // Only admins can view all SOS events
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }

    db.all('SELECT * FROM sos_events ORDER BY timestamp DESC', (err, events) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch SOS events' });
        }
        res.json(events);
    });
});

// Get single SOS event
app.get('/api/sos/:id', authenticateToken, (req, res) => {
    db.get('SELECT * FROM sos_events WHERE id = ?', [req.params.id], (err, sos) => {
        if (err || !sos) {
            return res.status(404).json({ error: 'SOS event not found' });
        }
        res.json(sos);
    });
});

// ==============================================
// NOTIFICATION FUNCTIONS
// ==============================================

function sendSOSNotifications(rideId, sosId) {
    console.log(`🚨 SOS ALERT - Ride: ${rideId}, SOS: ${sosId}`);
    
    // Get ride details
    db.get('SELECT * FROM rides WHERE id = ?', [rideId], (err, ride) => {
        if (!ride) return;

        // Get rider details
        db.get('SELECT * FROM users WHERE id = ?', [ride.rider_id], (err, rider) => {
            if (!rider) return;

            console.log('📧 Sending email notifications...');
            console.log('📱 Sending SMS to:', rider.emergency_contact);
            console.log('☎️ Initiating emergency call...');

            // TODO: Implement with Twilio and SendGrid
            // sendSMS(rider.emergency_contact, 'Emergency alert!');
            // sendEmail('admin@shecab.com', 'SOS Alert', 'Emergency detected');
        });
    });
}

// ==============================================
// START SERVER
// ==============================================

app.listen(PORT, () => {
    console.log(`
    ╔════════════════════════════════════════╗
    ║     🚗 SheCab Backend Server         ║
    ╠════════════════════════════════════════╣
    ║  Server running on port ${PORT}         ║
    ║  API: http://localhost:${PORT}/api      ║
    ║  Frontend: Place HTML in /public      ║
    ╚════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) console.error(err);
        console.log('\n👋 Database connection closed');
        process.exit(0);
    });
});