// ═══════════════════════════════════════════════════════════════════════════
// Healthcare Directory API - PostgreSQL Version for Render.com
// Node.js + Express + PostgreSQL + JWT + Bcrypt + Full CRUD + Role-Based Access
// ═══════════════════════════════════════════════════════════════════════════

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const SALT_ROUNDS = 12;

// PostgreSQL Configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Render.com
  }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Error connecting to PostgreSQL:', err);
  } else {
    console.log('✅ Connected to PostgreSQL:', res.rows[0].now);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Database Initialization
// ═══════════════════════════════════════════════════════════════════════════

async function initializeDatabase() {
  try {
    // Create tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS specialties (
        id SERIAL PRIMARY KEY,
        name_ar TEXT NOT NULL UNIQUE,
        name_en TEXT,
        icon TEXT DEFAULT '🏥',
        display_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS clinics (
        id SERIAL PRIMARY KEY,
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (specialty_id) REFERENCES specialties(id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS feedbacks (
        id SERIAL PRIMARY KEY,
        clinic_id INTEGER,
        clinic_name TEXT,
        feedback_type TEXT NOT NULL CHECK(feedback_type IN ('phone', 'address', 'hours', 'other')),
        message TEXT NOT NULL,
        contact TEXT,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'reviewing', 'applied', 'rejected')),
        admin_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP,
        FOREIGN KEY (clinic_id) REFERENCES clinics(id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS sync_logs (
        id SERIAL PRIMARY KEY,
        sync_type TEXT NOT NULL,
        records_updated INTEGER DEFAULT 0,
        sync_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        version INTEGER NOT NULL
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT DEFAULT 'editor',
        is_active INTEGER DEFAULT 1,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        message TEXT,
        clinic_id INTEGER,
        user_id INTEGER,
        type TEXT DEFAULT 'info',
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (clinic_id) REFERENCES clinics(id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS news (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        content TEXT,
        author TEXT,
        published_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create view
    await pool.query(`
      CREATE OR REPLACE VIEW clinics_full_info AS
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

    // Create default admin if not exists
    const adminCheck = await pool.query('SELECT id FROM admins WHERE username = $1', ['admin']);
    if (adminCheck.rows.length === 0) {
      const hash = await bcrypt.hash('admin123', SALT_ROUNDS);
      await pool.query(
        'INSERT INTO admins (username, password_hash, full_name, role) VALUES ($1, $2, $3, $4)',
        ['admin', hash, 'المشرف الرئيسي', 'super_admin']
      );
      console.log('✅ Default admin created: admin / admin123');
    } else {
      console.log('ℹ️ Default admin already exists');
    }

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

async function createNotification(title, message, clinicId = null, type = 'info') {
  try {
    const result = await pool.query(
      'INSERT INTO notifications (title, message, clinic_id, type) VALUES ($1, $2, $3, $4) RETURNING id',
      [title, message, clinicId, type]
    );
    return result.rows[0].id;
  } catch (err) {
    throw err;
  }
}

async function createNews(title, content, author, isActive = 1) {
  try {
    const result = await pool.query(
      'INSERT INTO news (title, content, author, is_active) VALUES ($1, $2, $3, $4) RETURNING id',
      [title, content, author, isActive]
    );
    return result.rows[0].id;
  } catch (err) {
    throw err;
  }
}

async function updateSyncVersion(type) {
  try {
    await pool.query(
      'INSERT INTO sync_logs (sync_type, records_updated, version) SELECT $1, 1, COALESCE(MAX(version), 0) + 1 FROM sync_logs',
      [type]
    );
  } catch (err) {
    console.error('Error updating sync version:', err);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public APIs (No Authentication Required)
// ═══════════════════════════════════════════════════════════════════════════

// Health check
app.get('/api/health', (req, res) => {
  pool.query('SELECT NOW()')
    .then(() => {
      res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '3.8',
        database: 'connected'
      });
    })
    .catch(err => {
      res.status(500).json({
        status: 'error',
        error: err.message,
        database: 'disconnected'
      });
    });
});

// Get all specialties
app.get('/api/specialties', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM specialties ORDER BY display_order');
    res.json({
      success: true,
      specialties: result.rows,
      count: result.rows.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all clinics with optional filters
app.get('/api/clinics', async (req, res) => {
  try {
    const { specialty_id, search, limit = 50, offset = 0 } = req.query;
    let sql = 'SELECT * FROM clinics_full_info WHERE 1=1';
    let params = [];
    let paramIndex = 1;

    if (specialty_id) {
      sql += ` AND specialty_id = $${paramIndex++}`;
      params.push(specialty_id);
    }

    if (search) {
      sql += ` AND (name ILIKE $${paramIndex} OR address ILIKE $${paramIndex} OR specialty_name ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    sql += ` ORDER BY name LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(sql, params);
    res.json({
      success: true,
      clinics: result.rows,
      count: result.rows.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single clinic by ID
app.get('/api/clinics/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clinics_full_info WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'العيادة غير موجودة' });
    }
    res.json({
      success: true,
      clinic: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Submit feedback
app.post('/api/feedbacks', async (req, res) => {
  try {
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

    const result = await pool.query(
      'INSERT INTO feedbacks (clinic_id, clinic_name, feedback_type, message, contact) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [clinic_id, clinic_name, feedback_type, message, contact || null]
    );

    res.status(201).json({
      success: true,
      message: 'شكراً لك! سيتم مراجعة ملاحظتك قريباً',
      id: result.rows[0].id
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get active news
app.get('/api/news', async (req, res) => {
  try {
    const { active = '1' } = req.query;
    let sql = 'SELECT * FROM news';
    let params = [];

    if (active === '1') {
      sql += ' WHERE is_active = 1';
    }

    sql += ' ORDER BY published_date DESC';

    const result = await pool.query(sql, params);
    res.json({
      success: true,
      news: result.rows,
      count: result.rows.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single news item
app.get('/api/news/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM news WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'الخبر غير موجود' });
    }
    res.json({
      success: true,
      news: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get notifications
app.get('/api/notifications', async (req, res) => {
  try {
    const { limit = 100, unread_only } = req.query;
    let sql = 'SELECT * FROM notifications';
    let params = [];

    if (unread_only === '1') {
      sql += ' WHERE is_read = 0';
    }

    sql += ' ORDER BY created_at DESC LIMIT $1';
    params.push(parseInt(limit));

    const result = await pool.query(sql, params);
    res.json({
      success: true,
      notifications: result.rows,
      count: result.rows.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Sync endpoint
app.get('/api/sync/export', async (req, res) => {
  try {
    const clientVersion = parseInt(req.query.version || 0);

    const versionResult = await pool.query('SELECT MAX(version) as version FROM sync_logs');
    const serverVersion = versionResult.rows[0]?.version || 0;

    if (clientVersion >= serverVersion) {
      return res.json({
        success: true,
        upToDate: true,
        version: serverVersion
      });
    }

    const [specialties, clinics, news] = await Promise.all([
      pool.query('SELECT * FROM specialties ORDER BY display_order'),
      pool.query('SELECT * FROM clinics_full_info'),
      pool.query('SELECT * FROM news WHERE is_active = 1 ORDER BY published_date DESC LIMIT 50')
    ]);

    res.json({
      success: true,
      version: serverVersion,
      timestamp: new Date().toISOString(),
      data: {
        specialties: specialties.rows,
        clinics: clinics.rows,
        news: news.rows
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Admin Authentication
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM admins WHERE username = $1 AND is_active = 1',
      [username]
    );

    const admin = result.rows[0];
    if (!admin) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }

    const isMatch = await bcrypt.compare(password, admin.password_hash);
    if (!isMatch) {
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

    await pool.query('UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [admin.id]);

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
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'خطأ في قاعدة البيانات' });
  }
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

  try {
    const result = await pool.query('SELECT * FROM admins WHERE id = $1', [req.admin.id]);
    const admin = result.rows[0];

    const isMatch = await bcrypt.compare(old_password, admin.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'كلمة المرور القديمة غير صحيحة' });
    }

    const hash = await bcrypt.hash(new_password, SALT_ROUNDS);
    await pool.query('UPDATE admins SET password_hash = $1 WHERE id = $2', [hash, req.admin.id]);

    res.json({ success: true, message: 'تم تغيير كلمة المرور بنجاح' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Admin Management (Super Admin Only)
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/admins', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, full_name, role, is_active, last_login, created_at FROM admins ORDER BY created_at DESC'
    );
    res.json({
      success: true,
      admins: result.rows,
      count: result.rows.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
    const result = await pool.query(
      'INSERT INTO admins (username, password_hash, full_name, role) VALUES ($1, $2, $3, $4) RETURNING id',
      [username, hash, full_name, role]
    );
    res.status(201).json({
      success: true,
      id: result.rows[0].id,
      message: 'تم إضافة المشرف بنجاح'
    });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'اسم المستخدم موجود بالفعل' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/admins/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
  const { username, full_name, role, is_active } = req.body;

  if (!username || !full_name || !role) {
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
  }

  try {
    const result = await pool.query(
      'UPDATE admins SET username = $1, full_name = $2, role = $3, is_active = $4 WHERE id = $5 RETURNING id',
      [username, full_name, role, is_active, req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'المشرف غير موجود' });
    }

    res.json({ success: true, message: 'تم تحديث المشرف بنجاح' });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'اسم المستخدم موجود بالفعل' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/admins/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
  if (parseInt(req.params.id) === req.admin.id) {
    return res.status(400).json({ error: 'لا يمكنك حذف نفسك' });
  }

  try {
    const result = await pool.query('DELETE FROM admins WHERE id = $1 RETURNING id', [req.params.id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'المشرف غير موجود' });
    }

    res.json({ success: true, message: 'تم حذف المشرف بنجاح' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Dashboard Statistics
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    const stats = {};

    const results = await Promise.all([
      pool.query('SELECT COUNT(*) as count FROM clinics'),
      pool.query('SELECT COUNT(*) as count FROM clinics WHERE is_active = 1'),
      pool.query('SELECT COUNT(*) as count FROM specialties'),
      pool.query("SELECT COUNT(*) as count FROM feedbacks WHERE status = 'pending'"),
      pool.query('SELECT COUNT(*) as count FROM feedbacks'),
      pool.query('SELECT MAX(created_at) as last FROM clinics'),
      pool.query('SELECT COUNT(*) as count FROM news WHERE is_active = 1'),
      pool.query('SELECT COUNT(*) as count FROM notifications WHERE is_read = 0'),
      pool.query('SELECT COUNT(*) as count FROM admins WHERE is_active = 1')
    ]);

    stats.clinics = results[0].rows[0].count;
    stats.activeClinics = results[1].rows[0].count;
    stats.specialties = results[2].rows[0].count;
    stats.pendingFeedback = results[3].rows[0].count;
    stats.totalFeedback = results[4].rows[0].count;
    stats.lastUpdate = results[5].rows[0].last;
    stats.activeNews = results[6].rows[0].count;
    stats.unreadNotifications = results[7].rows[0].count;
    stats.activeAdmins = results[8].rows[0].count;

    res.json({ success: true, stats });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Clinics Management
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/clinics', authenticateToken, requirePermission('clinics_view'), async (req, res) => {
  try {
    const { specialty_id, search } = req.query;
    let sql = `
      SELECT c.*, s.name_ar as specialty_name, s.icon as specialty_icon
      FROM clinics c
      LEFT JOIN specialties s ON c.specialty_id = s.id
      WHERE 1=1
    `;
    let params = [];
    let paramIndex = 1;

    if (specialty_id) {
      sql += ` AND c.specialty_id = $${paramIndex++}`;
      params.push(specialty_id);
    }

    if (search) {
      sql += ` AND (c.name ILIKE $${paramIndex} OR c.address ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    sql += ' ORDER BY c.last_updated DESC';

    const result = await pool.query(sql, params);
    res.json({ success: true, clinics: result.rows, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/clinics', authenticateToken, requirePermission('clinics_full'), async (req, res) => {
  const { name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes } = req.body;

  if (!name || !specialty_id || !phone || !address) {
    return res.status(400).json({ error: 'الاسم والتخصص والهاتف والعنوان مطلوبة' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO clinics
       (name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id`,
      [name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes]
    );

    const clinicId = result.rows[0].id;
    await updateSyncVersion('clinic_add');

    if (req.admin.role === 'super_admin') {
      try {
        const specialtyRow = await pool.query('SELECT name_ar FROM specialties WHERE id = $1', [specialty_id]);
        const specialtyName = specialtyRow.rows[0]?.name_ar || 'غير معروف';

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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/clinics/:id', authenticateToken, requirePermission('clinics_full'), async (req, res) => {
  const { name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes, is_active } = req.body;

  if (!name || !specialty_id || !phone || !address) {
    return res.status(400).json({ error: 'الاسم والتخصص والهاتف والعنوان مطلوبة' });
  }

  try {
    const result = await pool.query(
      `UPDATE clinics SET
       name = $1,
       specialty_id = $2,
       address = $3,
       phone = $4,
       phone_secondary = $5,
       working_hours = $6,
       working_days = $7,
       latitude = $8,
       longitude = $9,
       notes = $10,
       is_active = $11,
       last_updated = CURRENT_TIMESTAMP
       WHERE id = $12
       RETURNING id`,
      [name, specialty_id, address, phone, phone_secondary, working_hours, working_days, latitude, longitude, notes, is_active !== undefined ? is_active : 1, req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'العيادة غير موجودة' });
    }

    await updateSyncVersion('clinic_update');
    res.json({ success: true, message: 'تم تحديث العيادة بنجاح' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/clinics/:id', authenticateToken, requirePermission('clinics_full'), async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM clinics WHERE id = $1 RETURNING id', [req.params.id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'العيادة غير موجودة' });
    }

    await updateSyncVersion('clinic_delete');
    res.json({ success: true, message: 'تم حذف العيادة بنجاح' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Specialties Management
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/specialties', authenticateToken, requirePermission('clinics_view'), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM specialties ORDER BY display_order');
    res.json({ success: true, specialties: result.rows, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/specialties', authenticateToken, requirePermission('clinics_full'), async (req, res) => {
  const { name_ar, name_en, display_order, icon } = req.body;

  if (!name_ar) {
    return res.status(400).json({ error: 'الاسم بالعربي مطلوب' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO specialties (name_ar, name_en, display_order, icon) VALUES ($1, $2, $3, $4) RETURNING id',
      [name_ar, name_en, display_order || 0, icon || '🏥']
    );
    res.status(201).json({ success: true, id: result.rows[0].id, message: 'تمت إضافة التخصص' });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'اسم التخصص موجود بالفعل' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/specialties/:id', authenticateToken, requirePermission('clinics_full'), async (req, res) => {
  const { name_ar, name_en, display_order, icon } = req.body;

  try {
    const result = await pool.query(
      'UPDATE specialties SET name_ar = $1, name_en = $2, display_order = $3, icon = $4 WHERE id = $5 RETURNING id',
      [name_ar, name_en, display_order, icon, req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'التخصص غير موجود' });
    }

    res.json({ success: true, message: 'تم تحديث التخصص' });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'اسم التخصص موجود بالفعل' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/specialties/:id', authenticateToken, requirePermission('clinics_full'), async (req, res) => {
  try {
    const clinicCheck = await pool.query('SELECT COUNT(*) as count FROM clinics WHERE specialty_id = $1', [req.params.id]);
    if (clinicCheck.rows[0].count > 0) {
      return res.status(400).json({ error: 'لا يمكن حذف التخصص لأنه مرتبط بعيادات' });
    }

    const result = await pool.query('DELETE FROM specialties WHERE id = $1 RETURNING id', [req.params.id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'التخصص غير موجود' });
    }

    res.json({ success: true, message: 'تم حذف التخصص' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Feedbacks Management
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/feedbacks', authenticateToken, requirePermission('feedback_view'), async (req, res) => {
  try {
    const { status } = req.query;
    let sql = 'SELECT * FROM feedbacks';
    let params = [];

    if (status) {
      sql += ' WHERE status = $1';
      params.push(status);
    }

    sql += ' ORDER BY created_at DESC';

    const result = await pool.query(sql, params);
    res.json({ success: true, feedbacks: result.rows, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/feedbacks/:id', authenticateToken, requirePermission('feedback_view'), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM feedbacks WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'الملاحظة غير موجودة' });
    }
    res.json({ success: true, feedback: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/feedbacks/:id', authenticateToken, requirePermission('feedback_review'), async (req, res) => {
  const { status, admin_notes } = req.body;

  const validStatus = ['pending', 'reviewing', 'applied', 'rejected'];
  if (!validStatus.includes(status)) {
    return res.status(400).json({ error: 'حالة غير صالحة' });
  }

  try {
    const result = await pool.query(
      'UPDATE feedbacks SET status = $1, admin_notes = $2, reviewed_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING id',
      [status, admin_notes, req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'الملاحظة غير موجودة' });
    }

    res.json({ success: true, message: 'تم تحديث الحالة' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/feedbacks/:id', authenticateToken, requirePermission('feedback_full'), async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM feedbacks WHERE id = $1 RETURNING id', [req.params.id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'الملاحظة غير موجودة' });
    }

    res.json({ success: true, message: 'تم حذف الملاحظة' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// News Management
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/admin/news', authenticateToken, requireSuperAdmin, async (req, res) => {
  const { title, content, author, published_date, is_active } = req.body;

  if (!title || !content) {
    return res.status(400).json({ error: 'العنوان والمحتوى مطلوبان' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO news
       (title, content, author, published_date, is_active)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [title, content, author || req.admin.full_name, published_date || new Date().toISOString(), is_active !== undefined ? is_active : 1]
    );
    res.status(201).json({ success: true, id: result.rows[0].id, message: 'تمت إضافة الخبر بنجاح' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/news/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
  const { title, content, author, published_date, is_active } = req.body;

  try {
    const result = await pool.query(
      `UPDATE news SET
       title = $1,
       content = $2,
       author = $3,
       published_date = $4,
       is_active = $5
       WHERE id = $6
       RETURNING id`,
      [title, content, author, published_date, is_active, req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'الخبر غير موجود' });
    }

    res.json({ success: true, message: 'تم تحديث الخبر بنجاح' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/news/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM news WHERE id = $1 RETURNING id', [req.params.id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'الخبر غير موجود' });
    }

    res.json({ success: true, message: 'تم حذف الخبر بنجاح' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/news/:id/toggle', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE news SET is_active = 1 - is_active WHERE id = $1 RETURNING id',
      [req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'الخبر غير موجود' });
    }

    res.json({ success: true, message: 'تم تحديث حالة الخبر' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Notifications Management
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/notifications', authenticateToken, requirePermission('notifications_view'), async (req, res) => {
  try {
    const { limit = 100, unread_only } = req.query;
    let sql = 'SELECT * FROM notifications';
    let params = [];

    if (unread_only === '1') {
      sql += ' WHERE is_read = 0';
    }

    sql += ' ORDER BY created_at DESC LIMIT $1';
    params.push(parseInt(limit));

    const result = await pool.query(sql, params);
    res.json({ success: true, notifications: result.rows, count: result.rows.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/notifications/unread', authenticateToken, requirePermission('notifications_view'), async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) as count FROM notifications WHERE is_read = 0');
    res.json({ success: true, count: result.rows[0]?.count || 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/notifications', authenticateToken, requireSuperAdmin, async (req, res) => {
  const { title, message, clinic_id, type } = req.body;

  if (!title) {
    return res.status(400).json({ error: 'العنوان مطلوب' });
  }

  const validTypes = ['info', 'urgent', 'warning'];
  if (type && !validTypes.includes(type)) {
    return res.status(400).json({ error: 'نوع الإشعار غير صالح' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO notifications (title, message, clinic_id, type) VALUES ($1, $2, $3, $4) RETURNING id',
      [title, message, clinic_id || null, type || 'info']
    );
    res.status(201).json({ success: true, id: result.rows[0].id, message: 'تمت إضافة الإشعار بنجاح' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/notifications/:id/mark-read', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE notifications SET is_read = 1 WHERE id = $1 RETURNING id',
      [req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'الإشعار غير موجود' });
    }

    res.json({ success: true, message: 'تم تحديد الإشعار كمقروء' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/admin/notifications/mark-all-read', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'UPDATE notifications SET is_read = 1 WHERE is_read = 0 RETURNING id'
    );
    res.json({ success: true, message: `تم تحديد ${result.rowCount} إشعار كمقروء` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/notifications/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM notifications WHERE id = $1 RETURNING id', [req.params.id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'الإشعار غير موجود' });
    }

    res.json({ success: true, message: 'تم حذف الإشعار بنجاح' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Data Export
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/admin/export', authenticateToken, requirePermission('export'), async (req, res) => {
  try {
    const data = {};

    const results = await Promise.all([
      pool.query('SELECT * FROM clinics'),
      pool.query('SELECT * FROM specialties'),
      pool.query('SELECT * FROM news'),
      pool.query('SELECT * FROM notifications'),
      pool.query('SELECT * FROM feedbacks'),
      pool.query('SELECT id, username, full_name, role, is_active, last_login, created_at FROM admins')
    ]);

    data.clinics = results[0].rows;
    data.specialties = results[1].rows;
    data.news = results[2].rows;
    data.notifications = results[3].rows;
    data.feedbacks = results[4].rows;
    data.admins = results[5].rows;

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=clinics_backup_${new Date().toISOString().slice(0,10)}.json`);
    res.send(JSON.stringify(data, null, 2));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Diagnostic & Utility Routes
// ═══════════════════════════════════════════════════════════════════════════

// Test database connection
app.get('/api/test', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) as count FROM clinics');
    res.json({
      success: true,
      databaseConnected: true,
      clinicsCount: result.rows[0].count
    });
  } catch (err) {
    res.json({
      success: false,
      error: err.message,
      databaseConnected: false
    });
  }
});

// Detailed database test
app.get('/api/test-db', async (req, res) => {
  try {
    const connectionTest = await pool.query('SELECT 1');
    if (!connectionTest) {
      return res.json({
        success: false,
        error: 'Database connection failed',
        connected: false
      });
    }

    const tables = await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'");
    const views = await pool.query("SELECT table_name FROM information_schema.views WHERE table_schema = 'public'");

    res.json({
      success: true,
      connected: true,
      tables: tables.rows.map(row => row.table_name),
      views: views.rows.map(row => row.table_name),
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

process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await pool.end();
  console.log('✓ Database connection closed');
  process.exit(0);
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
