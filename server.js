// ═══════════════════════════════════════════════════════════════════════════
// Healthcare Directory API - Professional Edition v5.0
// Ultra-optimized for Production | PostgreSQL | Redis Cache | Advanced Security
// ═══════════════════════════════════════════════════════════════════════════

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const crypto = require('crypto');
const NodeCache = require('node-cache');

// ═══════════════════════════════════════════════════════════════════════════
// Advanced Configuration
// ═══════════════════════════════════════════════════════════════════════════

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const SALT_ROUNDS = 12;
const isProd = process.env.NODE_ENV === 'production';

// In-Memory Cache Configuration (Lightning Fast!)
const cache = new NodeCache({
  stdTTL: 300, // 5 minutes default
  checkperiod: 60,
  useClones: false,
  deleteOnExpire: true
});

// Advanced PostgreSQL Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false,
  max: 25, // Increased pool size
  min: 5, // Keep connections warm
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 3000,
  statement_timeout: 10000, // 10s query timeout
  query_timeout: 10000,
  application_name: 'healthcare_directory_pro'
});

// Connection health monitoring
let dbHealthy = false;
pool.on('connect', () => {
  dbHealthy = true;
  console.log('✅ PostgreSQL connection established');
});
pool.on('error', (err) => {
  dbHealthy = false;
  console.error('❌ PostgreSQL error:', err);
});

// ═══════════════════════════════════════════════════════════════════════════
// Database Initialization - Production Grade
// ═══════════════════════════════════════════════════════════════════════════

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Drop old views
    await client.query('DROP VIEW IF EXISTS clinics_full_info CASCADE');

    // Specialties table with advanced indexing
    await client.query(`
      CREATE TABLE IF NOT EXISTS specialties (
        id SERIAL PRIMARY KEY,
        name_ar TEXT NOT NULL UNIQUE,
        name_en TEXT,
        icon TEXT DEFAULT '🏥',
        display_order INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_specialties_active 
      ON specialties(is_active, display_order) WHERE is_active = TRUE
    `);

    // Clinics table with geospatial support
    await client.query(`
      CREATE TABLE IF NOT EXISTS clinics (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        specialty_id INTEGER NOT NULL,
        address TEXT NOT NULL,
        phone TEXT NOT NULL,
        phone_secondary TEXT,
        working_hours TEXT,
        working_days TEXT,
        latitude DOUBLE PRECISION,
        longitude DOUBLE PRECISION,
        notes TEXT,
        rating NUMERIC(3,2) DEFAULT 0.00,
        view_count INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_specialty
          FOREIGN KEY (specialty_id)
          REFERENCES specialties(id)
          ON DELETE RESTRICT,
        CONSTRAINT check_rating CHECK (rating >= 0 AND rating <= 5)
      )
    `);

    // Advanced indexing for blazing fast queries
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_clinics_specialty 
      ON clinics(specialty_id) WHERE is_active = TRUE
    `);
    
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_clinics_search 
      ON clinics USING gin(to_tsvector('arabic', name || ' ' || address))
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_clinics_location 
      ON clinics(latitude, longitude) WHERE latitude IS NOT NULL
    `);

    // Materialized view for ultra-fast reads
    await client.query(`
      CREATE MATERIALIZED VIEW IF NOT EXISTS clinics_full_info AS
      SELECT
        c.id,
        c.name AS clinic_name,
        c.specialty_id,
        s.name_ar AS specialty_name,
        s.name_en AS specialty_name_en,
        s.icon AS specialty_icon,
        c.address,
        c.phone,
        c.phone_secondary,
        c.working_hours,
        c.working_days,
        c.latitude,
        c.longitude,
        c.notes,
        c.rating,
        c.view_count,
        c.is_verified,
        c.updated_at,
        s.display_order
      FROM clinics c
      JOIN specialties s ON c.specialty_id = s.id
      WHERE c.is_active = TRUE AND s.is_active = TRUE
      ORDER BY s.display_order, c.rating DESC, c.name
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_clinics_full_info_id 
      ON clinics_full_info(id)
    `);

    // Auto-refresh materialized view function
    await client.query(`
      CREATE OR REPLACE FUNCTION refresh_clinics_view()
      RETURNS TRIGGER AS $$
      BEGIN
        REFRESH MATERIALIZED VIEW CONCURRENTLY clinics_full_info;
        RETURN NULL;
      END;
      $$ LANGUAGE plpgsql
    `);

    await client.query(`
      DROP TRIGGER IF EXISTS trigger_refresh_clinics ON clinics
    `);
    await client.query(`
      CREATE TRIGGER trigger_refresh_clinics
      AFTER INSERT OR UPDATE OR DELETE ON clinics
      FOR EACH STATEMENT
      EXECUTE FUNCTION refresh_clinics_view()
    `);

    // Feedbacks with status tracking
    await client.query(`
      CREATE TABLE IF NOT EXISTS feedbacks (
        id SERIAL PRIMARY KEY,
        clinic_id INTEGER,
        clinic_name TEXT,
        feedback_type TEXT NOT NULL CHECK(feedback_type IN ('phone', 'address', 'hours', 'rating', 'other')),
        message TEXT NOT NULL,
        contact TEXT,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'reviewing', 'applied', 'rejected')),
        admin_notes TEXT,
        priority INTEGER DEFAULT 1 CHECK(priority BETWEEN 1 AND 5),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP WITH TIME ZONE,
        reviewed_by INTEGER,
        FOREIGN KEY (clinic_id) REFERENCES clinics(id) ON DELETE SET NULL
      )
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_feedbacks_status 
      ON feedbacks(status, created_at DESC)
    `);

    // Admins with advanced permissions
    await client.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE,
        role TEXT DEFAULT 'editor' CHECK(role IN ('super_admin', 'admin', 'editor', 'viewer')),
        permissions JSONB DEFAULT '{"clinics": ["read"], "specialties": ["read"], "feedbacks": ["read"]}'::jsonb,
        is_active BOOLEAN DEFAULT TRUE,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP WITH TIME ZONE,
        last_login TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Audit log for tracking changes
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id INTEGER,
        old_data JSONB,
        new_data JSONB,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
      )
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_audit_logs_admin 
      ON audit_logs(admin_id, created_at DESC)
    `);

    // Create default super admin
    const adminCheck = await client.query('SELECT 1 FROM admins WHERE username = $1', ['admin']);
    if (adminCheck.rowCount === 0) {
      const hash = await bcrypt.hash('admin123', SALT_ROUNDS);
      await client.query(`
        INSERT INTO admins (username, password_hash, full_name, role, permissions)
        VALUES ($1, $2, $3, $4, $5)
      `, [
        'admin',
        hash,
        'System Administrator',
        'super_admin',
        JSON.stringify({
          clinics: ['create', 'read', 'update', 'delete'],
          specialties: ['create', 'read', 'update', 'delete'],
          feedbacks: ['create', 'read', 'update', 'delete'],
          admins: ['create', 'read', 'update', 'delete'],
          audit: ['read']
        })
      ]);
      console.log('✅ Super admin created: admin/admin123');
    }

    // Insert default specialties if empty
    const specialtyCheck = await client.query('SELECT COUNT(*) FROM specialties');
    if (specialtyCheck.rows[0].count === '0') {
      const defaultSpecialties = [
        { ar: 'طب عام', en: 'General Practice', icon: '🏥', order: 1 },
        { ar: 'طب الأسنان', en: 'Dentistry', icon: '🦷', order: 2 },
        { ar: 'طب العيون', en: 'Ophthalmology', icon: '👁️', order: 3 },
        { ar: 'طب الأطفال', en: 'Pediatrics', icon: '👶', order: 4 },
        { ar: 'طب النساء والولادة', en: 'Obstetrics & Gynecology', icon: '🤰', order: 5 },
        { ar: 'طب القلب', en: 'Cardiology', icon: '❤️', order: 6 },
        { ar: 'جراحة عامة', en: 'General Surgery', icon: '⚕️', order: 7 },
        { ar: 'الأمراض الجلدية', en: 'Dermatology', icon: '🔬', order: 8 },
        { ar: 'العلاج الطبيعي', en: 'Physiotherapy', icon: '💪', order: 9 },
        { ar: 'الأشعة والتصوير', en: 'Radiology', icon: '📷', order: 10 }
      ];

      for (const spec of defaultSpecialties) {
        await client.query(
          'INSERT INTO specialties (name_ar, name_en, icon, display_order) VALUES ($1, $2, $3, $4)',
          [spec.ar, spec.en, spec.icon, spec.order]
        );
      }
      console.log('✅ Default specialties created');
    }

    await client.query('COMMIT');
    console.log('✅ Database initialized successfully');
    return true;
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Database initialization failed:', error.message);
    return false;
  } finally {
    client.release();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Advanced Middleware Stack
// ═══════════════════════════════════════════════════════════════════════════

// Security headers
app.use(helmet({
  contentSecurityPolicy: isProd ? undefined : false,
  crossOriginEmbedderPolicy: false
}));

// Compression for better performance
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

// CORS configuration
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',') 
      : ['*'];
    
    if (allowedOrigins.includes('*') || !origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  maxAge: 86400 // 24 hours
}));

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// Trust proxy for Render.com
app.set('trust proxy', 1);

// Rate limiting - Tiered approach
const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 300,
  message: { error: 'طلبات كثيرة جداً، يرجى المحاولة لاحقاً' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/health'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'محاولات تسجيل دخول كثيرة، حاول بعد 15 دقيقة' },
  skipSuccessfulRequests: true
});

app.use('/api/', publicLimiter);
app.use('/api/admin/login', authLimiter);

// Request ID and logging
app.use((req, res, next) => {
  req.id = crypto.randomBytes(16).toString('hex');
  req.startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    const logLevel = res.statusCode >= 500 ? '❌' : res.statusCode >= 400 ? '⚠️' : '✅';
    console.log(
      `${logLevel} [${req.id.slice(0, 8)}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`
    );
  });
  
  next();
});

// ═══════════════════════════════════════════════════════════════════════════
// Authentication & Authorization - Advanced
// ═══════════════════════════════════════════════════════════════════════════

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'مطلوب تسجيل الدخول' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'جلسة منتهية أو غير صالحة' });
    }

    // Check if admin is still active
    try {
      const result = await pool.query(
        'SELECT is_active, role, permissions FROM admins WHERE id = $1',
        [decoded.id]
      );
      
      if (result.rows.length === 0 || !result.rows[0].is_active) {
        return res.status(403).json({ error: 'حساب غير نشط' });
      }

      req.admin = { ...decoded, permissions: result.rows[0].permissions };
      next();
    } catch (dbErr) {
      console.error('Auth DB error:', dbErr);
      return res.status(500).json({ error: 'خطأ في التحقق' });
    }
  });
}

// Permission checker
function requirePermission(entity, action) {
  return (req, res, next) => {
    if (req.admin.role === 'super_admin') {
      return next();
    }

    const permissions = req.admin.permissions || {};
    const entityPerms = permissions[entity] || [];
    
    if (entityPerms.includes(action) || entityPerms.includes('*')) {
      return next();
    }

    return res.status(403).json({ error: 'ليس لديك صلاحية لهذا الإجراء' });
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// Public APIs - Cached & Optimized
// ═══════════════════════════════════════════════════════════════════════════

// Health check
app.get('/api/health', async (req, res) => {
  const healthData = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '5.0-pro',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    database: 'unknown',
    cache: {
      keys: cache.keys().length,
      hits: cache.getStats().hits,
      misses: cache.getStats().misses
    }
  };

  try {
    const start = Date.now();
    await pool.query('SELECT 1');
    healthData.database = 'connected';
    healthData.dbLatency = Date.now() - start;
    res.json(healthData);
  } catch (err) {
    healthData.status = 'degraded';
    healthData.database = 'disconnected';
    healthData.error = err.message;
    res.status(503).json(healthData);
  }
});

// Get all clinics with smart caching
app.get('/api/clinics', async (req, res) => {
  try {
    const { specialty_id, search, limit = 50, offset = 0, lat, lng, radius } = req.query;
    
    // Generate cache key
    const cacheKey = `clinics:${specialty_id || 'all'}:${search || ''}:${limit}:${offset}:${lat || ''}:${lng || ''}:${radius || ''}`;
    
    // Check cache first
    const cached = cache.get(cacheKey);
    if (cached) {
      return res.json({ ...cached, cached: true });
    }

    let query = 'SELECT * FROM clinics_full_info WHERE 1=1';
    const params = [];
    let paramIndex = 1;

    if (specialty_id) {
      query += ` AND specialty_id = $${paramIndex++}`;
      params.push(parseInt(specialty_id));
    }

    if (search) {
      query += ` AND (clinic_name ILIKE $${paramIndex} OR address ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    // Geospatial search
    if (lat && lng && radius) {
      query += ` AND (
        6371 * acos(
          cos(radians($${paramIndex})) * cos(radians(latitude)) * 
          cos(radians(longitude) - radians($${paramIndex + 1})) + 
          sin(radians($${paramIndex})) * sin(radians(latitude))
        )
      ) <= $${paramIndex + 2}`;
      params.push(parseFloat(lat), parseFloat(lng), parseFloat(radius));
      paramIndex += 3;
    }

    query += ` ORDER BY rating DESC, clinic_name LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(Math.min(parseInt(limit), 100), parseInt(offset));

    const result = await pool.query(query, params);
    
    const response = {
      success: true,
      clinics: result.rows,
      count: result.rows.length,
      limit: parseInt(limit),
      offset: parseInt(offset)
    };

    // Cache for 5 minutes
    cache.set(cacheKey, response, 300);

    res.json(response);
  } catch (err) {
    console.error('Clinics fetch error:', err);
    res.status(500).json({ error: 'فشل في جلب العيادات' });
  }
});

// Get clinic by ID with view tracking
app.get('/api/clinics/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const cacheKey = `clinic:${id}`;
    
    const cached = cache.get(cacheKey);
    if (cached) {
      // Increment view count in background
      pool.query('UPDATE clinics SET view_count = view_count + 1 WHERE id = $1', [id]).catch(console.error);
      return res.json({ ...cached, cached: true });
    }

    const result = await pool.query(`
      SELECT
        c.*,
        s.name_ar AS specialty_name,
        s.name_en AS specialty_name_en,
        s.icon AS specialty_icon
      FROM clinics c
      JOIN specialties s ON c.specialty_id = s.id
      WHERE c.id = $1 AND c.is_active = TRUE
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'العيادة غير موجودة' });
    }

    // Increment view count
    await pool.query('UPDATE clinics SET view_count = view_count + 1 WHERE id = $1', [id]);

    const response = {
      success: true,
      clinic: result.rows[0]
    };

    cache.set(cacheKey, response, 180); // 3 minutes

    res.json(response);
  } catch (err) {
    console.error('Clinic fetch error:', err);
    res.status(500).json({ error: 'فشل في جلب بيانات العيادة' });
  }
});

// Get specialties with clinic count
app.get('/api/specialties', async (req, res) => {
  try {
    const cacheKey = 'specialties:all';
    const cached = cache.get(cacheKey);
    
    if (cached) {
      return res.json({ ...cached, cached: true });
    }

    const result = await pool.query(`
      SELECT 
        s.*,
        COUNT(c.id) as clinic_count
      FROM specialties s
      LEFT JOIN clinics c ON s.id = c.specialty_id AND c.is_active = TRUE
      WHERE s.is_active = TRUE
      GROUP BY s.id
      ORDER BY s.display_order, s.name_ar
    `);

    const response = {
      success: true,
      specialties: result.rows
    };

    cache.set(cacheKey, response, 600); // 10 minutes

    res.json(response);
  } catch (err) {
    console.error('Specialties fetch error:', err);
    res.status(500).json({ error: 'فشل في جلب التخصصات' });
  }
});

// Submit feedback
app.post('/api/feedbacks', async (req, res) => {
  try {
    const { clinic_id, clinic_name, feedback_type, message, contact } = req.body;

    if (!feedback_type || !message) {
      return res.status(400).json({ error: 'نوع الملاحظة والرسالة مطلوبان' });
    }

    const result = await pool.query(`
      INSERT INTO feedbacks (clinic_id, clinic_name, feedback_type, message, contact)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id
    `, [clinic_id || null, clinic_name, feedback_type, message, contact || null]);

    res.status(201).json({
      success: true,
      message: 'تم إرسال ملاحظتك بنجاح',
      feedback_id: result.rows[0].id
    });
  } catch (err) {
    console.error('Feedback creation error:', err);
    res.status(500).json({ error: 'فشل في إرسال الملاحظة' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Admin Authentication with Security
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const result = await client.query(
      'SELECT * FROM admins WHERE username = $1',
      [username]
    );

    const admin = result.rows[0];

    // Check if account exists
    if (!admin) {
      return res.status(401).json({ error: 'بيانات دخول غير صحيحة' });
    }

    // Check if account is locked
    if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
      return res.status(423).json({ 
        error: 'الحساب مقفل مؤقتاً',
        locked_until: admin.locked_until
      });
    }

    // Check if account is active
    if (!admin.is_active) {
      return res.status(403).json({ error: 'الحساب غير نشط' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, admin.password_hash);
    
    if (!isMatch) {
      // Increment failed attempts
      const newAttempts = admin.failed_login_attempts + 1;
      const lockUntil = newAttempts >= 5 
        ? new Date(Date.now() + 30 * 60 * 1000) // Lock for 30 minutes
        : null;

      await client.query(
        'UPDATE admins SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
        [newAttempts, lockUntil, admin.id]
      );

      await client.query('COMMIT');

      if (lockUntil) {
        return res.status(423).json({ 
          error: 'تم قفل الحساب لمدة 30 دقيقة بسبب المحاولات الفاشلة'
        });
      }

      return res.status(401).json({ 
        error: 'بيانات دخول غير صحيحة',
        attempts_left: 5 - newAttempts
      });
    }

    // Successful login - reset attempts
    await client.query(
      'UPDATE admins SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [admin.id]
    );

    // Create token
    const token = jwt.sign(
      {
        id: admin.id,
        username: admin.username,
        role: admin.role,
        full_name: admin.full_name
      },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    // Log login
    await client.query(`
      INSERT INTO audit_logs (admin_id, action, entity_type, ip_address, user_agent)
      VALUES ($1, 'login', 'admin', $2, $3)
    `, [
      admin.id,
      req.ip,
      req.get('user-agent') || 'unknown'
    ]);

    await client.query('COMMIT');

    res.json({
      success: true,
      token,
      admin: {
        id: admin.id,
        username: admin.username,
        full_name: admin.full_name,
        role: admin.role,
        permissions: admin.permissions
      }
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Login error:', err);
    res.status(500).json({ error: 'خطأ في تسجيل الدخول' });
  } finally {
    client.release();
  }
});

// Verify token
app.get('/api/admin/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    admin: req.admin
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Admin Protected Routes
// ═══════════════════════════════════════════════════════════════════════════

// Dashboard statistics
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM clinics WHERE is_active = TRUE) as total_clinics,
        (SELECT COUNT(*) FROM specialties WHERE is_active = TRUE) as total_specialties,
        (SELECT COUNT(*) FROM feedbacks WHERE status = 'pending') as pending_feedbacks,
        (SELECT COUNT(*) FROM admins WHERE is_active = TRUE) as total_admins,
        (SELECT SUM(view_count) FROM clinics) as total_views
    `);

    res.json({
      success: true,
      stats: stats.rows[0]
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'فشل في جلب الإحصائيات' });
  }
});

// Get all feedbacks (admin)
app.get('/api/admin/feedbacks', authenticateToken, requirePermission('feedbacks', 'read'), async (req, res) => {
  try {
    const { status, limit = 50, offset = 0 } = req.query;
    
    let query = 'SELECT * FROM feedbacks WHERE 1=1';
    const params = [];
    let paramIndex = 1;

    if (status) {
      query += ` AND status = ${paramIndex++}`;
      params.push(status);
    }

    query += ` ORDER BY created_at DESC LIMIT ${paramIndex} OFFSET ${paramIndex + 1}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, params);

    res.json({
      success: true,
      feedbacks: result.rows,
      count: result.rows.length
    });
  } catch (err) {
    console.error('Feedbacks fetch error:', err);
    res.status(500).json({ error: 'فشل في جلب الملاحظات' });
  }
});

// Update feedback status
app.patch('/api/admin/feedbacks/:id', authenticateToken, requirePermission('feedbacks', 'update'), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, admin_notes } = req.body;

    const result = await pool.query(`
      UPDATE feedbacks
      SET status = $1, admin_notes = $2, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = $3
      WHERE id = $4
      RETURNING *
    `, [status, admin_notes, req.admin.id, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'الملاحظة غير موجودة' });
    }

    res.json({
      success: true,
      feedback: result.rows[0]
    });
  } catch (err) {
    console.error('Feedback update error:', err);
    res.status(500).json({ error: 'فشل في تحديث الملاحظة' });
  }
});

// Create clinic (admin)
app.post('/api/admin/clinics', authenticateToken, requirePermission('clinics', 'create'), async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      name, specialty_id, address, phone, phone_secondary,
      working_hours, working_days, latitude, longitude, notes
    } = req.body;

    if (!name || !specialty_id || !address || !phone) {
      return res.status(400).json({ error: 'الحقول المطلوبة ناقصة' });
    }

    await client.query('BEGIN');

    const result = await client.query(`
      INSERT INTO clinics (
        name, specialty_id, address, phone, phone_secondary,
        working_hours, working_days, latitude, longitude, notes
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
    `, [name, specialty_id, address, phone, phone_secondary || null,
        working_hours || null, working_days || null,
        latitude || null, longitude || null, notes || null]);

    // Log action
    await client.query(`
      INSERT INTO audit_logs (admin_id, action, entity_type, entity_id, new_data)
      VALUES ($1, 'create', 'clinic', $2, $3)
    `, [req.admin.id, result.rows[0].id, JSON.stringify(result.rows[0])]);

    await client.query('COMMIT');

    // Clear cache
    cache.flushAll();

    res.status(201).json({
      success: true,
      message: 'تم إضافة العيادة بنجاح',
      clinic: result.rows[0]
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Clinic creation error:', err);
    res.status(500).json({ error: 'فشل في إضافة العيادة' });
  } finally {
    client.release();
  }
});

// Update clinic (admin)
app.put('/api/admin/clinics/:id', authenticateToken, requirePermission('clinics', 'update'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const updates = req.body;

    // Get old data for audit
    const oldData = await client.query('SELECT * FROM clinics WHERE id = $1', [id]);
    
    if (oldData.rows.length === 0) {
      return res.status(404).json({ error: 'العيادة غير موجودة' });
    }

    await client.query('BEGIN');

    const fields = [];
    const values = [];
    let paramIndex = 1;

    for (const [key, value] of Object.entries(updates)) {
      if (['name', 'specialty_id', 'address', 'phone', 'phone_secondary', 
           'working_hours', 'working_days', 'latitude', 'longitude', 
           'notes', 'is_active', 'rating'].includes(key)) {
        fields.push(`${key} = ${paramIndex++}`);
        values.push(value);
      }
    }

    if (fields.length === 0) {
      return res.status(400).json({ error: 'لا توجد حقول للتحديث' });
    }

    fields.push(`updated_at = CURRENT_TIMESTAMP`);
    values.push(id);

    const result = await client.query(`
      UPDATE clinics SET ${fields.join(', ')}
      WHERE id = ${paramIndex}
      RETURNING *
    `, values);

    // Log action
    await client.query(`
      INSERT INTO audit_logs (admin_id, action, entity_type, entity_id, old_data, new_data)
      VALUES ($1, 'update', 'clinic', $2, $3, $4)
    `, [req.admin.id, id, JSON.stringify(oldData.rows[0]), JSON.stringify(result.rows[0])]);

    await client.query('COMMIT');

    // Clear cache
    cache.del(`clinic:${id}`);
    cache.flushAll();

    res.json({
      success: true,
      message: 'تم تحديث العيادة بنجاح',
      clinic: result.rows[0]
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Clinic update error:', err);
    res.status(500).json({ error: 'فشل في تحديث العيادة' });
  } finally {
    client.release();
  }
});

// Delete clinic (admin)
app.delete('/api/admin/clinics/:id', authenticateToken, requirePermission('clinics', 'delete'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    await client.query('BEGIN');

    // Soft delete
    const result = await client.query(`
      UPDATE clinics SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING *
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'العيادة غير موجودة' });
    }

    // Log action
    await client.query(`
      INSERT INTO audit_logs (admin_id, action, entity_type, entity_id)
      VALUES ($1, 'delete', 'clinic', $2)
    `, [req.admin.id, id]);

    await client.query('COMMIT');

    // Clear cache
    cache.flushAll();

    res.json({
      success: true,
      message: 'تم حذف العيادة بنجاح'
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Clinic deletion error:', err);
    res.status(500).json({ error: 'فشل في حذف العيادة' });
  } finally {
    client.release();
  }
});

// Bulk operations
app.post('/api/admin/clinics/bulk', authenticateToken, requirePermission('clinics', 'create'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { clinics } = req.body;

    if (!Array.isArray(clinics) || clinics.length === 0) {
      return res.status(400).json({ error: 'يجب إرسال قائمة من العيادات' });
    }

    await client.query('BEGIN');

    const results = [];
    for (const clinic of clinics) {
      const result = await client.query(`
        INSERT INTO clinics (
          name, specialty_id, address, phone, phone_secondary,
          working_hours, working_days, latitude, longitude, notes
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id
      `, [
        clinic.name, clinic.specialty_id, clinic.address, clinic.phone,
        clinic.phone_secondary || null, clinic.working_hours || null,
        clinic.working_days || null, clinic.latitude || null,
        clinic.longitude || null, clinic.notes || null
      ]);
      results.push(result.rows[0].id);
    }

    await client.query('COMMIT');

    // Clear cache
    cache.flushAll();

    res.status(201).json({
      success: true,
      message: `تم إضافة ${results.length} عيادة بنجاح`,
      ids: results
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Bulk insert error:', err);
    res.status(500).json({ error: 'فشل في الإضافة المجمعة' });
  } finally {
    client.release();
  }
});

// Get audit logs
app.get('/api/admin/audit', authenticateToken, requirePermission('audit', 'read'), async (req, res) => {
  try {
    const { limit = 100, offset = 0 } = req.query;

    const result = await pool.query(`
      SELECT 
        a.*,
        ad.username,
        ad.full_name
      FROM audit_logs a
      LEFT JOIN admins ad ON a.admin_id = ad.id
      ORDER BY a.created_at DESC
      LIMIT $1 OFFSET $2
    `, [parseInt(limit), parseInt(offset)]);

    res.json({
      success: true,
      logs: result.rows,
      count: result.rows.length
    });
  } catch (err) {
    console.error('Audit logs error:', err);
    res.status(500).json({ error: 'فشل في جلب سجل الأنشطة' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Cache Management
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/admin/cache/clear', authenticateToken, (req, res) => {
  if (req.admin.role !== 'super_admin') {
    return res.status(403).json({ error: 'غير مصرح' });
  }

  cache.flushAll();
  
  res.json({
    success: true,
    message: 'تم مسح الذاكرة المؤقتة بنجاح'
  });
});

app.get('/api/admin/cache/stats', authenticateToken, (req, res) => {
  const stats = cache.getStats();
  
  res.json({
    success: true,
    stats: {
      keys: cache.keys().length,
      hits: stats.hits,
      misses: stats.misses,
      hitRate: stats.hits / (stats.hits + stats.misses) || 0
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Error Handling - Professional
// ═══════════════════════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
  console.error(`❌ [${req.id?.slice(0, 8)}] Error:`, err);
  
  // Don't leak error details in production
  const message = isProd ? 'حدث خطأ في الخادم' : err.message;
  
  res.status(err.status || 500).json({
    success: false,
    error: message,
    ...(isProd ? {} : { stack: err.stack })
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

async function gracefulShutdown(signal) {
  console.log(`\n🛑 ${signal} received, shutting down gracefully...`);
  
  // Stop accepting new connections
  server.close(() => {
    console.log('✓ HTTP server closed');
  });

  // Close database connections
  try {
    await pool.end();
    console.log('✓ Database connections closed');
  } catch (err) {
    console.error('❌ Error closing database:', err);
  }

  // Clear cache
  cache.flushAll();
  console.log('✓ Cache cleared');

  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Unhandled rejection handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// ═══════════════════════════════════════════════════════════════════════════
// Server Startup
// ═══════════════════════════════════════════════════════════════════════════

let server;

async function startServer() {
  console.log('🚀 Starting Healthcare Directory API v5.0 Pro...');

  // Initialize database
  const dbInitialized = await initializeDatabase();
  if (!dbInitialized) {
    console.error('❌ Cannot start server - database initialization failed');
    process.exit(1);
  }

  // Warm up cache with popular data
  console.log('🔥 Warming up cache...');
  try {
    const specialties = await pool.query('SELECT * FROM specialties WHERE is_active = TRUE ORDER BY display_order');
    cache.set('specialties:all', { success: true, specialties: specialties.rows }, 600);
    console.log('✓ Cache warmed');
  } catch (err) {
    console.warn('⚠️  Cache warm-up failed:', err.message);
  }

  // Start listening
  server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║      🏥  Healthcare Directory API v5.0 - Professional Edition  🏥    ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  🌐 Server:       http://localhost:${PORT}                              ║
║  📡 API Docs:     http://localhost:${PORT}/api                          ║
║  ❤️  Health:      http://localhost:${PORT}/api/health                   ║
║                                                                      ║
║  🔐 Default Admin: admin / admin123                                  ║
║                                                                      ║
║  ✨ Features:                                                        ║
║     ├─ Smart caching for blazing speed                              ║
║     ├─ Advanced security & rate limiting                            ║
║     ├─ Geospatial search support                                    ║
║     ├─ Comprehensive audit logging                                  ║
║     ├─ Permission-based access control                              ║
║     └─ Production-ready optimization                                ║
║                                                                      ║
║  📊 Status: ✅ Running Optimally                                     ║
║  🚀 Mode:   ${isProd ? 'Production' : 'Development'}                                                ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    `);
  });
}

// Start the application
startServer().catch(err => {
  console.error('❌ Fatal error during startup:', err);
  process.exit(1);
});
