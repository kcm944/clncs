// ═══════════════════════════════════════════════════════════════════════════
// Healthcare Directory API - Enhanced Version 3.8 (Complete Fix)
// Node.js + Express + SQLite + JWT + Bcrypt + Full CRUD + Role-Based Access
// ═══════════════════════════════════════════════════════════════════════════

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

const app = express();
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const SALT_ROUNDS = 12;

// Database configuration
const DB_FILENAME = 'clinics.db';
const dbPath = path.join(__dirname, DB_FILENAME);

// Global database variable
let db;

// ═══════════════════════════════════════════════════════════════════════════
// Database Utilities
// ═══════════════════════════════════════════════════════════════════════════

function verifyDatabaseFile() {
    try {
        if (!fs.existsSync(dbPath)) {
            console.log('ℹ️ Database file not found. Creating:', dbPath);
            fs.writeFileSync(dbPath, '');
        }

        try {
            fs.accessSync(dbPath, fs.constants.R_OK);
        } catch (err) {
            console.error('❌ Database file is not readable:', dbPath);
            return false;
        }

        try {
            fs.accessSync(dbPath, fs.constants.W_OK);
        } catch (err) {
            console.error('❌ Database file is not writable:', dbPath);
            return false;
        }

        const stats = fs.statSync(dbPath);
        if (stats.size === 0) {
            console.log('ℹ️ Database file is empty. Will initialize schema.');
            return true;
        }

        return true;
    } catch (error) {
        console.error('❌ Error verifying database file:', error.message);
        return false;
    }
}

function connectToDatabase() {
    return new Promise((resolve, reject) => {
        db = new sqlite3.Database(dbPath, (err) => {
            if (err) {
                console.error('❌ Database connection failed:', err.message);
                return reject(err);
            }
            console.log('✅ Database connection established');
            resolve();
        });
    });
}

async function initializeDatabaseSchema() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run("BEGIN TRANSACTION");
            
            // Create specialties table
            db.run(`CREATE TABLE IF NOT EXISTS specialties (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name_ar TEXT NOT NULL UNIQUE,
                name_en TEXT,
                icon TEXT DEFAULT '🏥',
                display_order INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);
            
            // Create clinics table
            db.run(`CREATE TABLE IF NOT EXISTS clinics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                specialty_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                phone TEXT NOT NULL,
                phone_secondary TEXT,
                working_hours TEXT,
                working_days TEXT,
                latitude REAL,
                longitude REAL,
                notes TEXT,
                is_active INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (specialty_id) REFERENCES specialties(id)
            )`);
            
            // Create feedbacks table
            db.run(`CREATE TABLE IF NOT EXISTS feedbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                clinic_id INTEGER,
                clinic_name TEXT,
                feedback_type TEXT NOT NULL CHECK(feedback_type IN ('phone', 'address', 'hours', 'other')),
                message TEXT NOT NULL,
                contact TEXT,
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'reviewing', 'applied', 'rejected')),
                admin_notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                reviewed_at DATETIME,
                FOREIGN KEY (clinic_id) REFERENCES clinics(id)
            )`);
            
            // Create sync_logs table
            db.run(`CREATE TABLE IF NOT EXISTS sync_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_type TEXT NOT NULL,
                records_updated INTEGER DEFAULT 0,
                sync_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                version INTEGER NOT NULL
            )`);
            
            // Create admins table
            db.run(`CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'editor',
                is_active INTEGER DEFAULT 1,
                last_login DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);
            
            // Create notifications table
            db.run(`CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                message TEXT,
                clinic_id INTEGER,
                user_id INTEGER,
                type TEXT DEFAULT 'info',
                is_read INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (clinic_id) REFERENCES clinics(id)
            )`);
            
            // Create news table
            db.run(`CREATE TABLE IF NOT EXISTS news (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT,
                author TEXT,
                published_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`);
            
            // Create clinics_full_info view
            db.run(`CREATE VIEW IF NOT EXISTS clinics_full_info AS
                SELECT 
                    c.id,
                    c.name,
                    c.specialty_id,
                    s.name_ar as specialty_name,
                    s.icon as specialty_icon,
                    c.address,
                    c.phone,
                    c.phone_secondary,
                    c.working_hours,
                    c.working_days,
                    c.latitude,
                    c.longitude,
                    c.notes,
                    c.is_active,
                    c.last_updated
                FROM clinics c
                JOIN specialties s ON c.specialty_id = s.id
                WHERE c.is_active = 1
                ORDER BY s.display_order, c.name
            `);
            
            db.run("COMMIT", (err) => {
                if (err) {
                    console.error("❌ Transaction failed:", err.message);
                    reject(err);
                } else {
                    console.log("✅ Database schema initialized successfully");
                    resolve();
                }
            });
        });
    });
}

async function createDefaultAdmin() {
    return new Promise((resolve, reject) => {
        const defaultAdmin = {
            username: 'admin',
            password: 'admin123',
            full_name: 'المشرف الرئيسي',
            role: 'super_admin'
        };

        db.get("SELECT id FROM admins WHERE username = ?", [defaultAdmin.username], async (err, row) => {
            if (err) {
                console.error("❌ Error checking admin:", err.message);
                return reject(err);
            }
            
            if (!row) {
                try {
                    const hash = await bcrypt.hash(defaultAdmin.password, SALT_ROUNDS);
                    db.run(
                        "INSERT INTO admins (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
                        [defaultAdmin.username, hash, defaultAdmin.full_name, defaultAdmin.role],
                        function(err) {
                            if (err) {
                                console.error("❌ Error creating default admin:", err.message);
                                reject(err);
                            } else {
                                console.log("✅ Default admin created: admin / admin123");
                                resolve();
                            }
                        }
                    );
                } catch (hashError) {
                    console.error("❌ Error hashing password:", hashError.message);
                    reject(hashError);
                }
            } else {
                console.log("ℹ️ Default admin already exists");
                resolve();
            }
        });
    });
}

async function initializeDatabase() {
    try {
        if (!verifyDatabaseFile()) {
            throw new Error('Database file verification failed');
        }

        await connectToDatabase();
        await initializeDatabaseSchema();
        await createDefaultAdmin();

        console.log('✅ Database initialization complete');
        return true;
    } catch (error) {
        console.error('❌ Database initialization failed:', error.message);
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Middleware
// ═══════════════════════════════════════════════════════════════════════════

app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static('public'));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', limiter);

app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
    });
    next();
});

// ═══════════════════════════════════════════════════════════════════════════
// Authentication & Authorization
// ═══════════════════════════════════════════════════════════════════════════

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'غير مصرح - يجب تسجيل الدخول' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.log('Token verification failed:', err.message);
            return res.status(403).json({ error: 'رمز دخول غير صالح أو منتهي الصلاحية' });
        }
        req.admin = decoded;
        next();
    });
}

const permissions = {
    super_admin: ['manage_admins', 'clinics_full', 'feedback_full', 'news_full', 'notifications_full', 'export'],
    editor: ['clinics_full', 'feedback_review', 'news_view', 'notifications_view'],
    viewer: ['clinics_view', 'feedback_view', 'news_view', 'notifications_view']
};

function hasPermission(admin, requiredPermission) {
    if (!admin || !admin.role) return false;
    const rolePerms = permissions[admin.role] || [];
    return rolePerms.includes(requiredPermission);
}

function requirePermission(permission) {
    return (req, res, next) => {
        if (!hasPermission(req.admin, permission)) {
            return res.status(403).json({ error: 'لا تملك الصلاحية الكافية لهذا الإجراء' });
        }
        next();
    };
}

function requireSuperAdmin(req, res, next) {
    if (req.admin.role !== 'super_admin') {
        return res.status(403).json({ error: 'يتطلب صلاحيات مشرف رئيسي' });
    }
    next();
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════

function createNotification(title, message, clinicId = null, type = 'info') {
    return new Promise((resolve, reject) => {
        const sql = `INSERT INTO notifications (title, message, clinic_id, type) VALUES (?, ?, ?, ?)`;
        db.run(sql, [title, message, clinicId, type], function(err) {
            if (err) reject(err);
            else resolve(this.lastID);
        });
    });
}

function createNews(title, content, author, isActive = 1) {
    return new Promise((resolve, reject) => {
        const sql = `INSERT INTO news (title, content, author, is_active) VALUES (?, ?, ?, ?)`;
        db.run(sql, [title, content, author, isActive], function(err) {
            if (err) reject(err);
            else resolve(this.lastID);
        });
    });
}

function updateSyncVersion(type) {
    return new Promise((resolve) => {
        db.run(
            'INSERT INTO sync_logs (sync_type, records_updated, version) SELECT ?, 1, COALESCE(MAX(version), 0) + 1 FROM sync_logs',
            [type],
            function() {
                resolve();
            }
        );
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// Public APIs (No Authentication Required)
// ═══════════════════════════════════════════════════════════════════════════

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '3.8',
        database: db ? 'connected' : 'disconnected'
    });
});

// Get all specialties
app.get('/api/specialties', (req, res) => {
    db.all('SELECT * FROM specialties ORDER BY display_order', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({
            success: true,
            specialties: rows,
            count: rows.length
        });
    });
});

// Get all clinics with optional filters
app.get('/api/clinics', (req, res) => {
    const { specialty_id, search, limit = 50, offset = 0 } = req.query;
    let sql = 'SELECT * FROM clinics_full_info WHERE 1=1';
    let params = [];

    if (specialty_id) {
        sql += ' AND specialty_id = ?';
        params.push(specialty_id);
    }

    if (search) {
        sql += ' AND (name LIKE ? OR address LIKE ? OR specialty_name LIKE ?)';
        const searchTerm = `%${search}%`;
        params.push(searchTerm, searchTerm, searchTerm);
    }

    sql += ' ORDER BY name LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({
            success: true,
            clinics: rows,
            count: rows.length
        });
    });
});

// Get single clinic by ID
app.get('/api/clinics/:id', (req, res) => {
    db.get('SELECT * FROM clinics_full_info WHERE id = ?', [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'العيادة غير موجودة' });
        res.json({
            success: true,
            clinic: row
        });
    });
});

// Submit feedback
app.post('/api/feedbacks', (req, res) => {
    const { clinic_id, clinic_name, feedback_type, message, contact } = req.body;

    if (!feedback_type || !message) {
        return res.status(400).json({ error: 'نوع الملاحظة والرسالة مطلوبان' });
    }

    const validTypes = ['phone', 'address', 'hours', 'other'];
    if (!validTypes.includes(feedback_type)) {
        return res.status(400).json({
            error: 'نوع الملاحظة غير صالح. يجب أن يكون أحد القيم التالية: phone, address, hours, other'
        });
    }

    const sql = `INSERT INTO feedbacks (clinic_id, clinic_name, feedback_type, message, contact)
                 VALUES (?, ?, ?, ?, ?)`;

    db.run(sql, [clinic_id, clinic_name, feedback_type, message, contact || null], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({
            success: true,
            message: 'شكراً لك! سيتم مراجعة ملاحظتك قريباً',
            id: this.lastID
        });
    });
});

// Get active news
app.get('/api/news', (req, res) => {
    const { active = '1' } = req.query;
    let sql = 'SELECT * FROM news';
    let params = [];

    if (active === '1') {
        sql += ' WHERE is_active = 1';
    }

    sql += ' ORDER BY published_date DESC';

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({
            success: true,
            news: rows,
            count: rows.length
        });
    });
});

// Get single news item
app.get('/api/news/:id', (req, res) => {
    db.get('SELECT * FROM news WHERE id = ?', [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'الخبر غير موجود' });
        res.json({
            success: true,
            news: row
        });
    });
});

// Get notifications
app.get('/api/notifications', (req, res) => {
    const { limit = 100, unread_only } = req.query;
    let sql = 'SELECT * FROM notifications';
    let params = [];

    if (unread_only === '1') {
        sql += ' WHERE is_read = 0';
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({
            success: true,
            notifications: rows,
            count: rows.length
        });
    });
});

// Sync endpoint
app.get('/api/sync/export', (req, res) => {
    const clientVersion = parseInt(req.query.version || 0);

    db.get('SELECT MAX(version) as version FROM sync_logs', [], (err, versionRow) => {
        if (err) return res.status(500).json({ error: err.message });

        const serverVersion = versionRow?.version || 0;

        if (clientVersion >= serverVersion) {
            return res.json({
                success: true,
                upToDate: true,
                version: serverVersion
            });
        }

        Promise.all([
            new Promise((resolve) => {
                db.all('SELECT * FROM specialties ORDER BY display_order', (err, rows) => {
                    resolve(rows || []);
                });
            }),
            new Promise((resolve) => {
                db.all('SELECT * FROM clinics_full_info', (err, rows) => {
                    resolve(rows || []);
                });
            }),
            new Promise((resolve) => {
                db.all('SELECT * FROM news WHERE is_active = 1 ORDER BY published_date DESC LIMIT 50', (err, rows) => {
                    resolve(rows || []);
                });
            })
        ]).then(([specialties, clinics, news]) => {
            res.json({
                success: true,
                version: serverVersion,
                timestamp: new Date().toISOString(),
                data: { specialties, clinics, news }
            });
        });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Admin Authentication
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;

    console.log('Login attempt:', { username, hasPassword: !!password });

    if (!username || !password) {
        return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
    }

    db.get('SELECT * FROM admins WHERE username = ? AND is_active = 1', [username], (err, admin) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'خطأ في قاعدة البيانات' });
        }
        
        if (!admin) {
            console.log('Admin not found:', username);
            return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
        }

        bcrypt.compare(password, admin.password_hash, (err, isMatch) => {
            if (err || !isMatch) {
                console.log('Password mismatch for:', username);
                return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
            }

            const token = jwt.sign(
                {
                    id: admin.id,
                    username: admin.username,
                    role: admin.role,
                    full_name: admin.full_name
                },
                JWT_SECRET,
                { expiresIn: '8h' }
            );

            db.run('UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [admin.id]);

            console.log('Login successful:', username, 'Role:', admin.role);

            res.json({
                success: true,
                token,
                admin: {
                    id: admin.id,
                    username: admin.username,
                    full_name: admin.full_name,
                    role: admin.role
                }
            });
        });
    });
});

// Get current admin info
app.get('/api/admin/me', authenticateToken, (req, res) => {
    res.json({
        success: true,
        admin: req.admin
    });
});

// Change password
app.post('/api/admin/change-password', authenticateToken, async (req, res) => {
    const { old_password, new_password } = req.body;

    if (!old_password || !new_password) {
        return res.status(400).json({ error: 'كلمة المرور القديمة والجديدة مطلوبتان' });
    }

    if (new_password.length < 6) {
        return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    }

    db.get('SELECT * FROM admins WHERE id = ?', [req.admin.id], async (err, admin) => {
        if (err || !admin) {
            return res.status(500).json({ error: 'خطأ في جلب بيانات المستخدم' });
        }

        const isMatch = await bcrypt.compare(old_password, admin.password_hash);
        if (!isMatch) {
            return res.status(401).json({ error: 'كلمة المرور القديمة غير صحيحة' });
        }

        const hash = await bcrypt.hash(new_password, SALT_ROUNDS);
        db.run('UPDATE admins SET password_hash = ? WHERE id = ?', [hash, req.admin.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, message: 'تم تغيير كلمة المرور بنجاح' });
        });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Admin Management (Super Admin Only)
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/admins', authenticateToken, requireSuperAdmin, (req, res) => {
    db.all('SELECT id, username, full_name, role, is_active, last_login, created_at FROM admins ORDER BY created_at DESC', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({
            success: true,
            admins: rows,
            count: rows.length
        });
    });
});

app.post('/api/admin/admins', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { username, password, full_name, role } = req.body;

    if (!username || !password || !full_name || !role) {
        return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }

    if (!['super_admin', 'editor', 'viewer'].includes(role)) {
        return res.status(400).json({ error: 'دور غير صالح' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    }

    try {
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        const sql = `INSERT INTO admins (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)`;

        db.run(sql, [username, hash, full_name, role], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(409).json({ error: 'اسم المستخدم موجود بالفعل' });
                }
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({
                success: true,
                id: this.lastID,
                message: 'تم إضافة المشرف بنجاح'
            });
        });
    } catch (err) {
        res.status(500).json({ error: 'خطأ في تشفير كلمة المرور' });
    }
});

app.put('/api/admin/admins/:id', authenticateToken, requireSuperAdmin, (req, res) => {
    const { username, full_name, role, is_active } = req.body;

    if (!username || !full_name || !role) {
        return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }

    const sql = `UPDATE admins SET username = ?, full_name = ?, role = ?, is_active = ? WHERE id = ?`;
    db.run(sql, [username, full_name, role, is_active, req.params.id], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE')) {
                return res.status(409).json({ error: 'اسم المستخدم موجود بالفعل' });
            }
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) return res.status(404).json({ error: 'المشرف غير موجود' });
        res.json({ success: true, message: 'تم تحديث المشرف بنجاح' });
    });
});

app.delete('/api/admin/admins/:id', authenticateToken, requireSuperAdmin, (req, res) => {
    if (parseInt(req.params.id) === req.admin.id) {
        return res.status(400).json({ error: 'لا يمكنك حذف نفسك' });
    }

    db.run('DELETE FROM admins WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'المشرف غير موجود' });
        res.json({ success: true, message: 'تم حذف المشرف بنجاح' });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Dashboard Statistics
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', authenticateToken, (req, res) => {
    const stats = {};

    Promise.all([
        new Promise((resolve) => db.get('SELECT COUNT(*) as count FROM clinics', (err, r) => { stats.clinics = r?.count || 0; resolve(); })),
        new Promise((resolve) => db.get('SELECT COUNT(*) as count FROM clinics WHERE is_active = 1', (err, r) => { stats.activeClinics = r?.count || 0; resolve(); })),
        new Promise((resolve) => db.get('SELECT COUNT(*) as count FROM specialties', (err, r) => { stats.specialties = r?.count || 0; resolve(); })),
        new Promise((resolve) => db.get("SELECT COUNT(*) as count FROM feedbacks WHERE status = 'pending'", (err, r) => { stats.pendingFeedback = r?.count || 0; resolve(); })),
        new Promise((resolve) => db.get('SELECT COUNT(*) as count FROM feedbacks', (err, r) => { stats.totalFeedback = r?.count || 0; resolve(); })),
        new Promise((resolve) => db.get('SELECT MAX(created_at) as last FROM clinics', (err, r) => { stats.lastUpdate = r?.last || null; resolve(); })),
        new Promise((resolve) => db.get('SELECT COUNT(*) as count FROM news WHERE is_active = 1', (err, r) => { stats.activeNews = r?.count || 0; resolve(); })),
        new Promise((resolve) => db.get('SELECT COUNT(*) as count FROM notifications WHERE is_read = 0', (err, r) => { stats.unreadNotifications = r?.count || 0; resolve(); })),
        new Promise((resolve) => db.get('SELECT COUNT(*) as count FROM admins WHERE is_active = 1', (err, r) => { stats.activeAdmins = r?.count || 0; resolve(); }))
    ]).then(() => {
        res.json({ success: true, stats });
    }).catch(err => {
        res.status(500).json({ error: err.message });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Clinics Management
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/clinics', authenticateToken, requirePermission('clinics_view'), (req, res) => {
    const { specialty_id, search } = req.query;
    let sql = `SELECT c.*, s.name_ar as specialty_name, s.icon as specialty_icon 
               FROM clinics c 
               LEFT JOIN specialties s ON c.specialty_id = s.id 
               WHERE 1=1`;
    let params = [];

    if (specialty_id) {
        sql += ' AND c.specialty_id = ?';
        params.push(specialty_id);
    }

    if (search) {
        sql += ' AND (c.name LIKE ? OR c.address LIKE ?)';
        const searchTerm = `%${search}%`;
        params.push(searchTerm, searchTerm);
    }

    sql += ' ORDER BY c.last_updated DESC';

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, clinics: rows, count: rows.length });
    });
});

app.post('/api/admin/clinics', authenticateToken, requirePermission('clinics_full'), async (req, res) => {
    const { name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes } = req.body;

    if (!name || !specialty_id || !phone || !address) {
        return res.status(400).json({ error: 'الاسم والتخصص والهاتف والعنوان مطلوبة' });
    }

    const sql = `INSERT INTO clinics (name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    db.run(sql, [name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes], async function(err) {
        if (err) return res.status(500).json({ error: err.message });

        const clinicId = this.lastID;
        await updateSyncVersion('clinic_add');

        if (req.admin.role === 'super_admin') {
            try {
                const specialtyRow = await new Promise((resolve) => {
                    db.get('SELECT name_ar FROM specialties WHERE id = ?', [specialty_id], (err, row) => {
                        resolve(row);
                    });
                });

                const specialtyName = specialtyRow?.name_ar || 'غير معروف';

                await createNotification(
                    `✅ عيادة جديدة: ${name}`,
                    `تمت إضافة عيادة ${name} (${specialtyName})`,
                    clinicId,
                    'info'
                );

                await createNews(
                    `🏥 عيادة جديدة: ${name}`,
                    `يسرنا الإعلان عن إضافة عيادة "${name}" في تخصص ${specialtyName}.\n\n📍 ${address}\n📞 ${phone}`,
                    req.admin.full_name,
                    1
                );
            } catch (e) {
                console.error('Error creating notification/news:', e);
            }
        }

        res.status(201).json({
            success: true,
            id: clinicId,
            message: 'تمت إضافة العيادة بنجاح'
        });
    });
});

app.put('/api/admin/clinics/:id', authenticateToken, requirePermission('clinics_full'), async (req, res) => {
    const { name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes, is_active } = req.body;

    if (!name || !specialty_id || !phone || !address) {
        return res.status(400).json({ error: 'الاسم والتخصص والهاتف والعنوان مطلوبة' });
    }

    const sql = `UPDATE clinics SET name = ?, specialty_id = ?, address = ?, phone = ?,
                 phone_secondary = ?, working_hours = ?, working_days = ?, latitude = ?,
                 longitude = ?, notes = ?, is_active = ?, last_updated = CURRENT_TIMESTAMP
                 WHERE id = ?`;

    db.run(sql, [name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes, is_active !== undefined ? is_active : 1, req.params.id], async function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'العيادة غير موجودة' });

        await updateSyncVersion('clinic_update');
        res.json({ success: true, message: 'تم تحديث العيادة بنجاح' });
    });
});

app.delete('/api/admin/clinics/:id', authenticateToken, requirePermission('clinics_full'), async (req, res) => {
    db.run('DELETE FROM clinics WHERE id = ?', [req.params.id], async function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'العيادة غير موجودة' });

        await updateSyncVersion('clinic_delete');
        res.json({ success: true, message: 'تم حذف العيادة بنجاح' });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Specialties Management
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/specialties', authenticateToken, requirePermission('clinics_view'), (req, res) => {
    db.all('SELECT * FROM specialties ORDER BY display_order', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, specialties: rows, count: rows.length });
    });
});

app.post('/api/admin/specialties', authenticateToken, requirePermission('clinics_full'), (req, res) => {
    const { name_ar, name_en, display_order, icon } = req.body;

    if (!name_ar) {
        return res.status(400).json({ error: 'الاسم بالعربي مطلوب' });
    }

    db.run('INSERT INTO specialties (name_ar, name_en, display_order, icon) VALUES (?, ?, ?, ?)',
           [name_ar, name_en, display_order || 0, icon || '🏥'], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE')) {
                return res.status(409).json({ error: 'اسم التخصص موجود بالفعل' });
            }
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ success: true, id: this.lastID, message: 'تمت إضافة التخصص' });
    });
});

app.put('/api/admin/specialties/:id', authenticateToken, requirePermission('clinics_full'), (req, res) => {
    const { name_ar, name_en, display_order, icon } = req.body;

    const sql = 'UPDATE specialties SET name_ar = ?, name_en = ?, display_order = ?, icon = ? WHERE id = ?';
    db.run(sql, [name_ar, name_en, display_order, icon, req.params.id], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE')) {
                return res.status(409).json({ error: 'اسم التخصص موجود بالفعل' });
            }
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) return res.status(404).json({ error: 'التخصص غير موجود' });
        res.json({ success: true, message: 'تم تحديث التخصص' });
    });
});

app.delete('/api/admin/specialties/:id', authenticateToken, requirePermission('clinics_full'), (req, res) => {
    db.get('SELECT COUNT(*) as count FROM clinics WHERE specialty_id = ?', [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row.count > 0) {
            return res.status(400).json({ error: 'لا يمكن حذف التخصص لأنه مرتبط بعيادات' });
        }

        db.run('DELETE FROM specialties WHERE id = ?', [req.params.id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: 'التخصص غير موجود' });
            res.json({ success: true, message: 'تم حذف التخصص' });
        });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Feedbacks Management
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/feedbacks', authenticateToken, requirePermission('feedback_view'), (req, res) => {
    const { status } = req.query;
    let sql = 'SELECT * FROM feedbacks';
    let params = [];

    if (status) {
        sql += ' WHERE status = ?';
        params.push(status);
    }

    sql += ' ORDER BY created_at DESC';

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, feedbacks: rows, count: rows.length });
    });
});

app.get('/api/admin/feedbacks/:id', authenticateToken, requirePermission('feedback_view'), (req, res) => {
    db.get('SELECT * FROM feedbacks WHERE id = ?', [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'الملاحظة غير موجودة' });
        res.json({ success: true, feedback: row });
    });
});

app.put('/api/admin/feedbacks/:id', authenticateToken, requirePermission('feedback_review'), (req, res) => {
    const { status, admin_notes } = req.body;

    const validStatus = ['pending', 'reviewing', 'applied', 'rejected'];
    if (!validStatus.includes(status)) {
        return res.status(400).json({ error: 'حالة غير صالحة' });
    }

    db.run('UPDATE feedbacks SET status = ?, admin_notes = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?',
           [status, admin_notes, req.params.id],
           function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'الملاحظة غير موجودة' });
        res.json({ success: true, message: 'تم تحديث الحالة' });
    });
});

app.delete('/api/admin/feedbacks/:id', authenticateToken, requirePermission('feedback_full'), (req, res) => {
    db.run('DELETE FROM feedbacks WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'الملاحظة غير موجودة' });
        res.json({ success: true, message: 'تم حذف الملاحظة' });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// News Management
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/admin/news', authenticateToken, requireSuperAdmin, (req, res) => {
    const { title, content, author, published_date, is_active } = req.body;

    if (!title || !content) {
        return res.status(400).json({ error: 'العنوان والمحتوى مطلوبان' });
    }

    const sql = `INSERT INTO news (title, content, author, published_date, is_active)
                 VALUES (?, ?, ?, ?, ?)`;

    db.run(sql, [title, content, author || req.admin.full_name, published_date || new Date().toISOString(), is_active !== undefined ? is_active : 1], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ success: true, id: this.lastID, message: 'تمت إضافة الخبر بنجاح' });
    });
});

app.put('/api/admin/news/:id', authenticateToken, requireSuperAdmin, (req, res) => {
    const { title, content, author, published_date, is_active } = req.body;

    const sql = `UPDATE news SET title = ?, content = ?, author = ?, published_date = ?, is_active = ? WHERE id = ?`;

    db.run(sql, [title, content, author, published_date, is_active, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'الخبر غير موجود' });
        res.json({ success: true, message: 'تم تحديث الخبر بنجاح' });
    });
});

app.delete('/api/admin/news/:id', authenticateToken, requireSuperAdmin, (req, res) => {
    db.run('DELETE FROM news WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'الخبر غير موجود' });
        res.json({ success: true, message: 'تم حذف الخبر بنجاح' });
    });
});

app.patch('/api/admin/news/:id/toggle', authenticateToken, requireSuperAdmin, (req, res) => {
    db.run('UPDATE news SET is_active = 1 - is_active WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'الخبر غير موجود' });
        res.json({ success: true, message: 'تم تحديث حالة الخبر' });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Notifications Management
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/notifications', authenticateToken, requirePermission('notifications_view'), (req, res) => {
    const { limit = 100, unread_only } = req.query;
    let sql = 'SELECT * FROM notifications';
    let params = [];

    if (unread_only === '1') {
        sql += ' WHERE is_read = 0';
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, notifications: rows, count: rows.length });
    });
});

app.get('/api/admin/notifications/unread', authenticateToken, requirePermission('notifications_view'), (req, res) => {
    db.get('SELECT COUNT(*) as count FROM notifications WHERE is_read = 0', (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, count: row?.count || 0 });
    });
});

app.post('/api/admin/notifications', authenticateToken, requireSuperAdmin, (req, res) => {
    const { title, message, clinic_id, type } = req.body;

    if (!title) {
        return res.status(400).json({ error: 'العنوان مطلوب' });
    }

    const validTypes = ['info', 'urgent', 'warning'];
    if (type && !validTypes.includes(type)) {
        return res.status(400).json({ error: 'نوع الإشعار غير صالح' });
    }

    const sql = `INSERT INTO notifications (title, message, clinic_id, type)
                 VALUES (?, ?, ?, ?)`;

    db.run(sql, [title, message, clinic_id || null, type || 'info'], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ success: true, id: this.lastID, message: 'تمت إضافة الإشعار بنجاح' });
    });
});

app.patch('/api/admin/notifications/:id/mark-read', authenticateToken, requireSuperAdmin, (req, res) => {
    db.run('UPDATE notifications SET is_read = 1 WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'الإشعار غير موجود' });
        res.json({ success: true, message: 'تم تحديد الإشعار كمقروء' });
    });
});

app.patch('/api/admin/notifications/mark-all-read', authenticateToken, requireSuperAdmin, (req, res) => {
    db.run('UPDATE notifications SET is_read = 1 WHERE is_read = 0', function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: `تم تحديد ${this.changes} إشعار كمقروء` });
    });
});

app.delete('/api/admin/notifications/:id', authenticateToken, requireSuperAdmin, (req, res) => {
    db.run('DELETE FROM notifications WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'الإشعار غير موجود' });
        res.json({ success: true, message: 'تم حذف الإشعار بنجاح' });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Data Export
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/export', authenticateToken, requirePermission('export'), (req, res) => {
    const data = {};

    Promise.all([
        new Promise((resolve) => db.all('SELECT * FROM clinics', (err, rows) => { data.clinics = rows || []; resolve(); })),
        new Promise((resolve) => db.all('SELECT * FROM specialties', (err, rows) => { data.specialties = rows || []; resolve(); })),
        new Promise((resolve) => db.all('SELECT * FROM news', (err, rows) => { data.news = rows || []; resolve(); })),
        new Promise((resolve) => db.all('SELECT * FROM notifications', (err, rows) => { data.notifications = rows || []; resolve(); })),
        new Promise((resolve) => db.all('SELECT * FROM feedbacks', (err, rows) => { data.feedbacks = rows || []; resolve(); })),
        new Promise((resolve) => db.all('SELECT id, username, full_name, role, is_active, last_login, created_at FROM admins', (err, rows) => { data.admins = rows || []; resolve(); }))
    ]).then(() => {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename=clinics_backup_${new Date().toISOString().slice(0,10)}.json`);
        res.send(JSON.stringify(data, null, 2));
    }).catch(err => {
        res.status(500).json({ error: err.message });
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Diagnostic & Utility Routes
// ═══════════════════════════════════════════════════════════════════════════

// Test database connection
app.get('/api/test', (req, res) => {
    if (!db) {
        return res.json({
            success: false,
            error: 'Database not connected',
            databaseConnected: false
        });
    }
    
    db.get('SELECT COUNT(*) as count FROM clinics', (err, row) => {
        if (err) {
            return res.json({
                success: false,
                error: err.message,
                databaseConnected: false
            });
        }
        res.json({
            success: true,
            databaseConnected: true,
            clinicsCount: row.count
        });
    });
});

// Detailed database test
app.get('/api/test-db', async (req, res) => {
    try {
        if (!db) {
            return res.json({
                success: false,
                error: 'Database not connected',
                connected: false
            });
        }

        const connectionTest = await new Promise((resolve) => {
            db.get('SELECT 1', (err) => {
                resolve({ connected: !err });
            });
        });

        if (!connectionTest.connected) {
            return res.json({
                success: false,
                error: 'Database connection failed',
                connected: false
            });
        }

        const tables = await new Promise((resolve) => {
            db.all("SELECT name FROM sqlite_master WHERE type='table'", (err, rows) => {
                resolve(rows ? rows.map(row => row.name) : []);
            });
        });

        const clinicColumns = await new Promise((resolve) => {
            db.all("PRAGMA table_info(clinics)", (err, rows) => {
                resolve(rows ? rows.map(col => col.name) : []);
            });
        });

        const views = await new Promise((resolve) => {
            db.all("SELECT name FROM sqlite_master WHERE type='view'", (err, rows) => {
                resolve(rows ? rows.map(row => row.name) : []);
            });
        });

        res.json({
            success: true,
            connected: true,
            tables: tables,
            clinicColumns: clinicColumns,
            views: views,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ═══════════════════════════════════════════════════════════════════════════
// Error Handling & 404
// ═══════════════════════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
    console.error('❌ Error:', err);
    res.status(err.status || 500).json({
        success: false,
        error: err.message || 'حدث خطأ في الخادم'
    });
});

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'المسار غير موجود'
    });
});

// ═══════════════════════════════════════════════════════════════════════════
// Graceful Shutdown
// ═══════════════════════════════════════════════════════════════════════════

process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down gracefully...');
    if (db) {
        db.close((err) => {
            if (err) {
                console.error('Error closing database:', err);
            } else {
                console.log('✓ Database connection closed');
            }
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
});

// ═══════════════════════════════════════════════════════════════════════════
// Start Server
// ═══════════════════════════════════════════════════════════════════════════

async function startServer() {
    console.log('🚀 Starting server initialization...');
    
    const dbInitialized = await initializeDatabase();
    if (!dbInitialized) {
        console.error('❌ Database initialization failed. Server cannot start.');
        process.exit(1);
    }

    app.listen(PORT, '0.0.0.0', () => {
        console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║       🏥 Healthcare Directory API v3.8 - Ready! 🏥           ║
╠═══════════════════════════════════════════════════════════════════╣
║  Server:  http://localhost:${PORT}                            ║
║  API:     http://localhost:${PORT}/api                        ║
║  Admin:   http://localhost:${PORT}/admin.html                 ║
║  Status:  ✓ Running & Secured                                ║
║  Default: admin / admin123                                    ║
╚═══════════════════════════════════════════════════════════════════╝
        `);
    });
}

// Start the server
startServer().catch(err => {
    console.error('❌ Server failed to start:', err);
    process.exit(1);
});
