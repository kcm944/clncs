// ═══════════════════════════════════════════════════════════════════════════
// Healthcare Directory API - Ultimate Optimized Version for Render.com
// Features: PostgreSQL, JWT Auth, Rate Limiting, CORS, Error Handling, Transactions
// ═══════════════════════════════════════════════════════════════════════════

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const SALT_ROUNDS = 12;

// Enhanced PostgreSQL Configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ═══════════════════════════════════════════════════════════════════════════
// Database Initialization with Transaction Support
// ═══════════════════════════════════════════════════════════════════════════

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Drop conflicting view if exists
    await client.query('DROP VIEW IF EXISTS clinics_full_info CASCADE');

    // Create tables with enhanced constraints
    await client.query(`
      CREATE TABLE IF NOT EXISTS specialties (
        id SERIAL PRIMARY KEY,
        name_ar TEXT NOT NULL UNIQUE,
        name_en TEXT,
        icon TEXT DEFAULT '🏥',
        display_order INTEGER DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

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
        latitude REAL,
        longitude REAL,
        notes TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_specialty
          FOREIGN KEY (specialty_id)
          REFERENCES specialties(id)
          ON DELETE RESTRICT
      )
    `);

    // Create view with clear column naming
    await client.query(`
      CREATE OR REPLACE VIEW clinics_full_info AS
      SELECT
        c.id,
        c.name AS clinic_name,
        c.specialty_id,
        s.name_ar AS specialty_name,
        s.icon AS specialty_icon,
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
      WHERE c.is_active = TRUE
      ORDER BY s.display_order, c.name
    `);

    // Create other tables
    await client.query(`
      CREATE TABLE IF NOT EXISTS feedbacks (
        id SERIAL PRIMARY KEY,
        clinic_id INTEGER,
        clinic_name TEXT,
        feedback_type TEXT NOT NULL CHECK(feedback_type IN ('phone', 'address', 'hours', 'other')),
        message TEXT NOT NULL,
        contact TEXT,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'reviewing', 'applied', 'rejected')),
        admin_notes TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP WITH TIME ZONE,
        FOREIGN KEY (clinic_id) REFERENCES clinics(id) ON DELETE SET NULL
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT DEFAULT 'editor' CHECK(role IN ('super_admin', 'editor', 'viewer')),
        is_active BOOLEAN DEFAULT TRUE,
        last_login TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create default admin if not exists
    const adminCheck = await client.query('SELECT 1 FROM admins WHERE username = $1', ['admin']);
    if (adminCheck.rowCount === 0) {
      const hash = await bcrypt.hash('admin123', SALT_ROUNDS);
      await client.query(
        'INSERT INTO admins (username, password_hash, full_name, role) VALUES ($1, $2, $3, $4)',
        ['admin', hash, 'Main Administrator', 'super_admin']
      );
      console.log('✅ Default admin created: admin/admin123');
    }

    await client.query('COMMIT');
    console.log('✅ Database initialization complete');
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
// Middleware with Security Enhancements
// ═══════════════════════════════════════════════════════════════════════════

app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS || '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Enhanced rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
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
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log('Token verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.admin = decoded;
    next();
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// Public APIs
// ═══════════════════════════════════════════════════════════════════════════

// Health check with database verification
app.get('/api/health', async (req, res) => {
  try {
    const dbResult = await pool.query('SELECT 1');
    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: '4.0',
      database: 'connected',
      dbTest: dbResult.rows[0]
    });
  } catch (err) {
    console.error('Health check error:', err);
    res.status(500).json({
      status: 'error',
      error: err.message,
      database: 'disconnected'
    });
  }
});

// Get all clinics using the fixed view
app.get('/api/clinics', async (req, res) => {
  try {
    const { specialty_id, search, limit = 50, offset = 0 } = req.query;
    let query = 'SELECT * FROM clinics_full_info WHERE 1=1';
    const params = [];
    let paramIndex = 1;

    if (specialty_id) {
      query += ` AND specialty_id = $${paramIndex++}`;
      params.push(specialty_id);
    }

    if (search) {
      query += ` AND (clinic_name ILIKE $${paramIndex} OR address ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex++;
    }

    query += ` ORDER BY clinic_name LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, params);
    res.json({
      success: true,
      clinics: result.rows,
      count: result.rows.length
    });
  } catch (err) {
    console.error('Clinics fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch clinics' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Admin Authentication
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM admins WHERE username = $1 AND is_active = TRUE',
      [username]
    );

    const admin = result.rows[0];
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, admin.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
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
    res.status(500).json({ error: 'Database error' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Error Handling
// ═══════════════════════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal server error'
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not found'
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Start Server
// ═══════════════════════════════════════════════════════════════════════════

async function startServer() {
  console.log('🚀 Starting Healthcare Directory API v4.0...');

  const dbInitialized = await initializeDatabase();
  if (!dbInitialized) {
    console.error('❌ Cannot start server due to database initialization failure');
    process.exit(1);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║       🏥 Healthcare Directory API v4.0 - Ready! 🏥           ║
╠═══════════════════════════════════════════════════════════════════╣
║  Server:  http://localhost:${PORT}                            ║
║  API:     http://localhost:${PORT}/api                        ║
║  Health:  http://localhost:${PORT}/api/health                 ║
║  Status:  ✓ Running & Secured                                ║
║  Default: admin / admin123                                    ║
╚═══════════════════════════════════════════════════════════════════╝
    `);
  });
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await pool.end();
  console.log('✓ Database connection closed');
  process.exit(0);
});

// Start the server
startServer().catch(err => {
  console.error('❌ Server failed to start:', err);
  process.exit(1);
});
