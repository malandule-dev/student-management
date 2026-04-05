require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'student-management-secret';

// ── MIDDLEWARE ────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── DATABASE ──────────────────────────────────────────
const db = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME     || 'student_management',
  port:     process.env.DB_PORT     || 3306,
  waitForConnections: true,
  connectionLimit: 10,
});

(async () => {
  try {
    await db.query('SELECT 1');
    console.log('✅ MySQL connected successfully');
  } catch (err) {
    console.error('❌ MySQL connection failed:', err.message);
    process.exit(1);
  }
})();

// ── AUTH MIDDLEWARE ───────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No token provided' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireTeacher(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'teacher')
      return res.status(403).json({ error: 'Teacher access required' });
    next();
  });
}

// ══════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.role, student_id: user.student_id },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, role: user.role, student_id: user.student_id } });
  } catch {
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, async (req, res) => {
  const [rows] = await db.query('SELECT id, name, email, role, student_id FROM users WHERE id = ?', [req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'User not found' });
  res.json(rows[0]);
});

// ══════════════════════════════════════════════════════
//  MARKS ROUTES
// ══════════════════════════════════════════════════════

// GET /api/marks — student gets their own marks
app.get('/api/marks', requireAuth, async (req, res) => {
  const studentId = req.user.student_id;
  const [rows] = await db.query(
    `SELECT m.id, s.name AS subject, m.term, m.mark, m.total, m.grade
     FROM marks m
     JOIN subjects s ON m.subject_id = s.id
     WHERE m.student_id = ?
     ORDER BY s.name, m.term`,
    [studentId]
  );
  res.json(rows);
});

// GET /api/marks/all — teacher gets all students marks
app.get('/api/marks/all', requireTeacher, async (req, res) => {
  const [rows] = await db.query(
    `SELECT m.id, u.name AS student_name, st.grade_level, s.name AS subject, m.term, m.mark, m.total, m.grade
     FROM marks m
     JOIN students st ON m.student_id = st.id
     JOIN users u ON st.user_id = u.id
     JOIN subjects s ON m.subject_id = s.id
     ORDER BY u.name, s.name, m.term`
  );
  res.json(rows);
});

// POST /api/marks — teacher adds a mark
app.post('/api/marks', requireTeacher, async (req, res) => {
  const { student_id, subject_id, term, mark, total } = req.body;
  if (!student_id || !subject_id || !term || mark === undefined || !total)
    return res.status(400).json({ error: 'All fields are required' });
  const percentage = (mark / total) * 100;
  let grade = 'F';
  if (percentage >= 80) grade = 'A';
  else if (percentage >= 70) grade = 'B';
  else if (percentage >= 60) grade = 'C';
  else if (percentage >= 50) grade = 'D';
  else if (percentage >= 40) grade = 'E';
  await db.query(
    'INSERT INTO marks (student_id, subject_id, term, mark, total, grade) VALUES (?, ?, ?, ?, ?, ?)',
    [student_id, subject_id, term, mark, total, grade]
  );
  res.status(201).json({ message: 'Mark added successfully' });
});

// DELETE /api/marks/:id — teacher deletes a mark
app.delete('/api/marks/:id', requireTeacher, async (req, res) => {
  await db.query('DELETE FROM marks WHERE id = ?', [req.params.id]);
  res.json({ message: 'Mark deleted' });
});

// ══════════════════════════════════════════════════════
//  SUBJECTS ROUTES
// ══════════════════════════════════════════════════════

// GET /api/subjects
app.get('/api/subjects', requireAuth, async (req, res) => {
  const [rows] = await db.query('SELECT * FROM subjects ORDER BY name');
  res.json(rows);
});

// ══════════════════════════════════════════════════════
//  STUDENTS ROUTES
// ══════════════════════════════════════════════════════

// GET /api/students — teacher gets all students
app.get('/api/students', requireTeacher, async (req, res) => {
  const [rows] = await db.query(
    `SELECT s.id, u.name, u.email, s.grade_level, s.student_number
     FROM students s JOIN users u ON s.user_id = u.id
     ORDER BY u.name`
  );
  res.json(rows);
});

// ══════════════════════════════════════════════════════
//  MESSAGES ROUTES
// ══════════════════════════════════════════════════════

// GET /api/messages — get messages for logged in user
app.get('/api/messages', requireAuth, async (req, res) => {
  let rows;
  if (req.user.role === 'teacher') {
    [rows] = await db.query(
      `SELECT m.*, u.name AS sender_name FROM messages m
       JOIN users u ON m.sender_id = u.id
       ORDER BY m.created_at ASC`
    );
  } else {
    [rows] = await db.query(
      `SELECT m.*, u.name AS sender_name FROM messages m
       JOIN users u ON m.sender_id = u.id
       WHERE m.student_user_id = ? OR m.sender_id = ?
       ORDER BY m.created_at ASC`,
      [req.user.id, req.user.id]
    );
  }
  res.json(rows);
});

// POST /api/messages — send a message
app.post('/api/messages', requireAuth, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message is required' });
  const studentUserId = req.user.role === 'student' ? req.user.id : req.body.student_user_id;
  await db.query(
    'INSERT INTO messages (sender_id, student_user_id, message, role) VALUES (?, ?, ?, ?)',
    [req.user.id, studentUserId, message, req.user.role]
  );
  res.status(201).json({ message: 'Message sent' });
});

// ══════════════════════════════════════════════════════
//  REPORT CARD ROUTE
// ══════════════════════════════════════════════════════
const PDFDocument = require('pdfkit');

app.get('/api/report-card', requireAuth, async (req, res) => {
  try {
    const studentId = req.user.student_id;

    // Get student info
    const [studentRows] = await db.query(
      `SELECT u.name, u.email, s.student_number, s.grade_level
       FROM users u JOIN students s ON s.user_id = u.id
       WHERE u.id = ?`, [req.user.id]
    );
    if (!studentRows.length) return res.status(404).json({ error: 'Student not found' });
    const student = studentRows[0];

    // Get marks
    const [marks] = await db.query(
      `SELECT m.*, s.name AS subject FROM marks m
       JOIN subjects s ON m.subject_id = s.id
       WHERE m.student_id = ? ORDER BY s.name, m.term`, [studentId]
    );

    // Create PDF
    const doc = new PDFDocument({ margin: 50 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="report-card-${student.student_number}.pdf"`);
    doc.pipe(res);

    // ── HEADER ──
    doc.rect(0, 0, 612, 120).fill('#060910');
    doc.fillColor('#00e5ff').font('Helvetica-Bold').fontSize(24)
       .text('STUDENT REPORT CARD', 50, 35, { align: 'center' });
    doc.fillColor('#7a8499').font('Helvetica').fontSize(11)
       .text('Student Management System — School', 50, 65, { align: 'center' });
    doc.fillColor('#e8eaf0').fontSize(10)
       .text(`Generated: ${new Date().toLocaleDateString('en-ZA')}`, 50, 85, { align: 'center' });

    // ── STUDENT INFO ──
    doc.moveDown(3);
    doc.rect(50, 135, 512, 80).fill('#0c1120').stroke('#1a56db');
    doc.fillColor('#00e5ff').font('Helvetica-Bold').fontSize(11)
       .text('STUDENT INFORMATION', 65, 148);
    doc.fillColor('#e8eaf0').font('Helvetica').fontSize(10);
    doc.text(`Name: ${student.name}`, 65, 168);
    doc.text(`Student No: ${student.student_number}`, 65, 183);
    doc.text(`Grade: ${student.grade_level}`, 300, 168);
    doc.text(`Email: ${student.email}`, 300, 183);

    // ── MARKS TABLE ──
    doc.moveDown(2);
    let y = 235;

    // Table header
    doc.rect(50, y, 512, 25).fill('#1a56db');
    doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(9);
    doc.text('SUBJECT', 60, y + 8);
    doc.text('TERM', 220, y + 8);
    doc.text('MARK', 300, y + 8);
    doc.text('TOTAL', 360, y + 8);
    doc.text('%', 420, y + 8);
    doc.text('GRADE', 470, y + 8);
    y += 25;

    // Table rows
    let totalPct = 0;
    let count = 0;
    marks.forEach((m, i) => {
      const pct = Math.round((m.mark / m.total) * 100);
      totalPct += pct;
      count++;
      const bg = i % 2 === 0 ? '#0f1826' : '#0c1120';
      doc.rect(50, y, 512, 22).fill(bg);

      // Grade color
      let gradeColor = '#ff6b6b';
      if (m.grade === 'A') gradeColor = '#00e5aa';
      else if (m.grade === 'B') gradeColor = '#00e5ff';
      else if (m.grade === 'C') gradeColor = '#7b61ff';
      else if (m.grade === 'D') gradeColor = 'orange';

      doc.fillColor('#e8eaf0').font('Helvetica').fontSize(9);
      doc.text(m.subject, 60, y + 7);
      doc.text(m.term, 220, y + 7);
      doc.text(m.mark.toString(), 300, y + 7);
      doc.text(m.total.toString(), 360, y + 7);
      doc.text(pct + '%', 420, y + 7);
      doc.fillColor(gradeColor).font('Helvetica-Bold').text(m.grade, 470, y + 7);
      y += 22;

      // New page if needed
      if (y > 700) {
        doc.addPage();
        y = 50;
      }
    });

    // ── SUMMARY ──
    y += 20;
    const overallAvg = count > 0 ? Math.round(totalPct / count) : 0;
    let overallGrade = 'F';
    if (overallAvg >= 80) overallGrade = 'A';
    else if (overallAvg >= 70) overallGrade = 'B';
    else if (overallAvg >= 60) overallGrade = 'C';
    else if (overallAvg >= 50) overallGrade = 'D';
    else if (overallAvg >= 40) overallGrade = 'E';

    doc.rect(50, y, 512, 50).fill('#0c1120').stroke('#1a56db');
    doc.fillColor('#00e5ff').font('Helvetica-Bold').fontSize(11)
       .text('OVERALL PERFORMANCE', 65, y + 10);
    doc.fillColor('#e8eaf0').font('Helvetica').fontSize(10)
       .text(`Average: ${overallAvg}%`, 65, y + 28);
    doc.fillColor(overallAvg >= 70 ? '#00e5aa' : overallAvg >= 50 ? '#00e5ff' : '#ff6b6b')
       .font('Helvetica-Bold').text(`Overall Grade: ${overallGrade}`, 300, y + 28);

    // ── FOOTER ──
    doc.rect(0, 780, 612, 62).fill('#060910');
    doc.fillColor('#7a8499').font('Helvetica').fontSize(9)
       .text('This report card was generated electronically and is valid without a signature.', 50, 795, { align: 'center' });
    doc.fillColor('#00e5ff').text('Student Management System', 50, 810, { align: 'center' });

    doc.end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to generate report card' });
  }
});

// ── PAGE ROUTES ───────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
app.get('/chat', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ── START SERVER ──────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Student Management System running at http://localhost:${PORT}`);
});