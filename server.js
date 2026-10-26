
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'student_management',
  waitForConnections: true,
  connectionLimit: 10
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'student-management-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 86400000,
    secure: process.env.NODE_ENV === 'production'
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Homepage
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Authentication
function auth(req, res, next) {
  if (!req.session.adminId) {
    return res.status(401).json({
      message: 'Please login first.'
    });
  }
  next();
}

// Initialize database
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(150) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS students (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      roll_number VARCHAR(30) NOT NULL UNIQUE,
      email VARCHAR(150) NOT NULL,
      phone VARCHAR(20),
      department VARCHAR(100),
      year VARCHAR(20),
      gender VARCHAR(20),
      section VARCHAR(20),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const email = (
    process.env.ADMIN_EMAIL || 'admin@example.com'
  ).trim().toLowerCase();

  const password = process.env.ADMIN_PASSWORD;

  if (!password) {
    throw new Error('Set ADMIN_PASSWORD in Render Environment.');
  }

  const [rows] = await pool.query(
    'SELECT id FROM admins WHERE email = ?',
    [email]
  );

  if (rows.length === 0) {
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO admins(email, password) VALUES(?, ?)',
      [email, hashedPassword]
    );

    console.log('Default admin account created.');
  }
}

// Signup
app.post('/api/signup', async (req, res) => {
  try {
    let { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: 'Email and password required.'
      });
    }

    email = email.trim().toLowerCase();

    if (password.length < 8) {
      return res.status(400).json({
        message: 'Password must contain at least 8 characters.'
      });
    }

    const [existing] = await pool.query(
      'SELECT id FROM admins WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        message: 'Email already registered. Please login.'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO admins(email, password) VALUES(?, ?)',
      [email, hashedPassword]
    );

    res.status(201).json({
      message: 'Account created successfully. Please login.'
    });

  } catch (error) {
    console.error('Signup error:', error);

    res.status(error.code === 'ER_DUP_ENTRY' ? 409 : 500).json({
      message: error.code === 'ER_DUP_ENTRY'
        ? 'Email already registered. Please login.'
        : 'Signup failed.'
    });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: 'Email and password required.'
      });
    }

    email = email.trim().toLowerCase();

    const [rows] = await pool.query(
      'SELECT * FROM admins WHERE email = ?',
      [email]
    );

    if (
      rows.length === 0 ||
      !(await bcrypt.compare(password, rows[0].password))
    ) {
      return res.status(401).json({
        message: 'Invalid email or password.'
      });
    }

    req.session.adminId = rows[0].id;

    res.json({
      message: 'Login successful.'
    });

  } catch (error) {
    console.error('Login error:', error);

    res.status(500).json({
      message: 'Login failed.'
    });
  }
});

// Check login
app.get('/api/auth', (req, res) => {
  res.json({
    loggedIn: !!req.session.adminId
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({
        message: 'Logout failed.'
      });
    }

    res.clearCookie('connect.sid');

    res.json({
      message: 'Logged out.'
    });
  });
});

// Get all students
app.get('/api/students', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM students ORDER BY id DESC'
    );

    res.json(rows);

  } catch (error) {
    console.error('GET STUDENTS ERROR:', error);

    res.status(500).json({
      message: 'Could not fetch students.'
    });
  }
});

// Get student by ID
app.get('/api/students/:id', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM students WHERE id = ?',
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        message: 'Student not found.'
      });
    }

    res.json(rows[0]);

  } catch (error) {
    console.error('GET STUDENT ERROR:', error);

    res.status(500).json({
      message: 'Could not fetch student.'
    });
  }
});

// Add student
app.post('/api/students', auth, async (req, res) => {
  try {
    const {
      name,
      roll_number,
      email,
      phone,
      department,
      year,
      gender,
      section
    } = req.body;

    if (!name || !roll_number || !email) {
      return res.status(400).json({
        message: 'Name, roll number and email required.'
      });
    }

    const [result] = await pool.query(
      `INSERT INTO students
      (name, roll_number, email, phone, department, year, gender, section)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        roll_number,
        email,
        phone || null,
        department || null,
        year || null,
        gender || null,
        section || null
      ]
    );

    res.status(201).json({
      message: 'Student added successfully.',
      id: result.insertId
    });

  } catch (error) {
    console.error('ADD STUDENT ERROR:', error);

    res.status(error.code === 'ER_DUP_ENTRY' ? 409 : 500).json({
      message: error.code === 'ER_DUP_ENTRY'
        ? 'Roll number already exists.'
        : 'Could not add student.'
    });
  }
});

// Update student
app.put('/api/students/:id', auth, async (req, res) => {
  try {
    const {
      name,
      roll_number,
      email,
      phone,
      department,
      year,
      gender,
      section
    } = req.body;

    if (!name || !roll_number || !email) {
      return res.status(400).json({
        message: 'Name, roll number and email required.'
      });
    }

    const [result] = await pool.query(
      `UPDATE students
       SET name = ?,
           roll_number = ?,
           email = ?,
           phone = ?,
           department = ?,
           year = ?,
           gender = ?,
           section = ?
       WHERE id = ?`,
      [
        name,
        roll_number,
        email,
        phone || null,
        department || null,
        year || null,
        gender || null,
        section || null,
        req.params.id
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        message: 'Student not found.'
      });
    }

    res.json({
      message: 'Student updated successfully.'
    });

  } catch (error) {
    console.error('UPDATE STUDENT ERROR:', error);

    res.status(error.code === 'ER_DUP_ENTRY' ? 409 : 500).json({
      message: error.code === 'ER_DUP_ENTRY'
        ? 'Roll number already exists.'
        : 'Could not update student.'
    });
  }
});

// Delete student
app.delete('/api/students/:id', auth, async (req, res) => {
  try {
    const [result] = await pool.query(
      'DELETE FROM students WHERE id = ?',
      [req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        message: 'Student not found.'
      });
    }

    res.json({
      message: 'Student deleted successfully.'
    });

  } catch (error) {
    console.error('DELETE STUDENT ERROR:', error);

    res.status(500).json({
      message: 'Could not delete student.'
    });
  }
});

// Start server
init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
    });
  })
  .catch(error => {
    console.error('Startup/database error:', error);
    process.exit(1);
  });
