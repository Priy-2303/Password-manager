const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

const JWT_SECRET = process.env.JWT_SECRET || 'nexus-vault-super-secure-jwt-secret-key-3035';
const IS_PROD = process.env.NODE_ENV === 'production';

// Enforce HTTPS in production reverse proxy
app.set('trust proxy', 1);
if (IS_PROD) {
    app.use((req, res, next) => {
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect(301, `https://${req.headers.host}${req.url}`);
        }
        next();
    });
}

// Security Headers & Content Security Policy (No inline scripts allowed)
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                fontSrc: ["'self'", "https://fonts.gstatic.com"],
                imgSrc: ["'self'", "data:"],
                connectSrc: ["'self'"],
                objectSrc: ["'none'"],
                frameAncestors: ["'none'"],
                baseUri: ["'self'"]
            }
        },
        hsts: IS_PROD ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false
    })
);

app.use(express.json());
app.use(cookieParser());

// Anti-caching for sensitive API endpoints
app.use('/api', (req, res, next) => {
    res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Surrogate-Control': 'no-store'
    });
    next();
});

// Serve frontend static assets
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiters
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Access rate limit exceeded. Cryo-lock active for 15 minutes.' }
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Vault traffic limit exceeded. Slow down.' }
});

// MySQL Connection Pool (Aiven SSL enabled)
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'nexus_vault',
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 3306,
    ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

async function initDatabase() {
    try {
        const connection = await pool.getConnection();

        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL UNIQUE,
                auth_hash VARCHAR(255) NOT NULL,
                salt VARCHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Automatic backward-compatibility migration for existing databases:
        try {
            const [pwdCols] = await connection.query("SHOW COLUMNS FROM users LIKE 'password_hash'");
            if (pwdCols.length > 0) {
                await connection.query("ALTER TABLE users MODIFY COLUMN password_hash VARCHAR(255) NULL DEFAULT NULL");
                console.log('[MIGRATION] Made legacy password_hash column nullable.');
            }
            const [authCols] = await connection.query("SHOW COLUMNS FROM users LIKE 'auth_hash'");
            if (authCols.length === 0) {
                await connection.query("ALTER TABLE users ADD COLUMN auth_hash VARCHAR(255) NULL");
                console.log('[MIGRATION] Added auth_hash column to existing users table.');
            }
            const [saltCols] = await connection.query("SHOW COLUMNS FROM users LIKE 'salt'");
            if (saltCols.length === 0) {
                await connection.query("ALTER TABLE users ADD COLUMN salt VARCHAR(64) NULL");
                console.log('[MIGRATION] Added salt column to existing users table.');
            }
        } catch (migErr) {
            console.log('[MIGRATION NOTICE]', migErr.message);
        }

        await connection.query(`
            CREATE TABLE IF NOT EXISTS vault_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(255) NOT NULL,
                encrypted_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        connection.release();
        console.log('[NEXUS CORE] Database schema verified and locked.');
    } catch (err) {
        console.error('[NEXUS CORE ERROR] Database initialization failed:', err.message);
    }
}

// Session authentication middleware (JWT via HttpOnly Secure Cookie)
function authenticateToken(req, res, next) {
    const token = req.cookies.nexus_session;
    if (!token) {
        return res.status(401).json({ error: 'SESSION_TERMINATED: Authentication required.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // { id, username }
        next();
    } catch (err) {
        return res.status(403).json({ error: 'SESSION_INVALID: Cryptographic token rejected.' });
    }
}

// 1. Fetch user salt for zero-knowledge key derivation
app.get('/api/auth/salt/:username', authLimiter, async (req, res) => {
    const { username } = req.params;
    try {
        const [rows] = await pool.query('SELECT salt FROM users WHERE username = ?', [username]);
        if (rows.length === 0) {
            // Constant-time synthetic salt to avoid user enumeration timing attacks
            return res.json({ salt: 'a7c93e4f8b2d1065e8a93b4d1c7e2f50' });
        }
        res.json({ salt: rows[0].salt });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'CORE_FAULT: Database query failed.' });
    }
});

// 2. Register User (Zero-knowledge: stores only bcrypt(clientAuthHash) + client salt)
app.post('/api/register', authLimiter, async (req, res) => {
    const { username, clientAuthHash, salt } = req.body;
    if (!username || !clientAuthHash || !salt) {
        return res.status(400).json({ error: 'INSUFFICIENT_DATA: Username, auth hash, and salt are required.' });
    }

    try {
        const serverHash = await bcrypt.hash(clientAuthHash, 12);
        const [result] = await pool.query(
            'INSERT INTO users (username, auth_hash, salt) VALUES (?, ?, ?)',
            [username, serverHash, salt]
        );

        const token = jwt.sign({ id: result.insertId, username }, JWT_SECRET, { expiresIn: '2h' });
        res.cookie('nexus_session', token, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: 'strict',
            maxAge: 2 * 60 * 60 * 1000
        });

        res.status(201).json({
            message: 'SECURITY_CORE_INITIALIZED',
            userId: result.insertId,
            username
        });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            res.status(409).json({ error: 'IDENTITY_CONFLICT: Username already registered.' });
        } else {
            console.error('Registration DB Error:', err);
            res.status(500).json({ error: `CORE_FAULT: ${err.sqlMessage || 'Storage operation failed.'}` });
        }
    }
});

// 3. Login User
app.post('/api/login', authLimiter, async (req, res) => {
    const { username, clientAuthHash } = req.body;
    if (!username || !clientAuthHash) {
        return res.status(400).json({ error: 'INSUFFICIENT_DATA: Credentials required.' });
    }

    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'AUTH_FAILED: Invalid identity or key.' });
        }

        const user = rows[0];
        const match = await bcrypt.compare(clientAuthHash, user.auth_hash);
        if (!match) {
            return res.status(401).json({ error: 'AUTH_FAILED: Cryptographic verification mismatch.' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
        res.cookie('nexus_session', token, {
            httpOnly: true,
            secure: IS_PROD,
            sameSite: 'strict',
            maxAge: 2 * 60 * 60 * 1000
        });

        res.json({
            message: 'ACCESS_GRANTED',
            userId: user.id,
            username: user.username
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'CORE_FAULT: Verification pipeline disrupted.' });
    }
});

// 4. Logout / Invalidate Session
app.post('/api/logout', (req, res) => {
    res.clearCookie('nexus_session', { httpOnly: true, secure: IS_PROD, sameSite: 'strict' });
    res.json({ message: 'ENCRYPTED_SESSION_TERMINATED' });
});

// 5. Check Active Session State
app.get('/api/session', authenticateToken, (req, res) => {
    res.json({
        active: true,
        user: { id: req.user.id, username: req.user.username }
    });
});

// 6. Get Vault Items (IDOR Protected: strict req.user.id)
app.get('/api/vault', authenticateToken, apiLimiter, async (req, res) => {
    const userId = req.user.id;
    try {
        const [rows] = await pool.query(
            'SELECT id, title, encrypted_data, created_at, updated_at FROM vault_items WHERE user_id = ? ORDER BY updated_at DESC',
            [userId]
        );
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'VAULT_ACCESS_ERROR: Could not retrieve encrypted blocks.' });
    }
});

// 7. Add Encrypted Vault Item
app.post('/api/vault', authenticateToken, apiLimiter, async (req, res) => {
    const { title, encryptedData } = req.body;
    const userId = req.user.id;

    if (!title || !encryptedData) {
        return res.status(400).json({ error: 'INVALID_PAYLOAD: Title and encrypted payload required.' });
    }

    try {
        const [result] = await pool.query(
            'INSERT INTO vault_items (user_id, title, encrypted_data) VALUES (?, ?, ?)',
            [userId, title, encryptedData]
        );
        res.status(201).json({
            message: 'AES_GCM_PROCESS_COMPLETE',
            itemId: result.insertId
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'VAULT_WRITE_ERROR: Failed to commit secret capsule.' });
    }
});

// 8. Delete Encrypted Vault Item
app.delete('/api/vault/:id', authenticateToken, apiLimiter, async (req, res) => {
    const itemId = req.params.id;
    const userId = req.user.id;

    try {
        const [result] = await pool.query(
            'DELETE FROM vault_items WHERE id = ? AND user_id = ?',
            [itemId, userId]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'CAPSULE_NOT_FOUND: Item does not exist or unauthorized.' });
        }
        res.json({ message: 'CAPSULE_PURGED: Encrypted block purged from storage.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'VAULT_PURGE_ERROR: Deletion failed.' });
    }
});

// Fallback to single page client
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`[NEXUS VAULT] Security Core listening online on port ${PORT}`);
    await initDatabase();
});
