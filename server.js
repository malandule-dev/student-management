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

// ── SETUP ROUTE ───────────────────────────────────────
app.get('/setup-passwords', async (req, res) => {
  try {
    const hash = await bcrypt.hash('password', 10);
    await db.query('UPDATE users SET password = ? WHERE email = ?', [hash, 'thabo@school.com']);
    await db.query('UPDATE users SET password = ? WHERE email = ?', [hash, 'teacher@school.com']);
    res.json({ message: 'Passwords updated successfully!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════

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

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const [rows] = await db.query('SELECT id, name, email, role, student_id FROM users WHERE id = ?', [req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'User not found' });
  res.json(rows[0]);
});

// ══════════════════════════════════════════════════════
//  MARKS ROUTES
// ══════════════════════════════════════════════════════

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

app.delete('/api/marks/:id', requireTeacher, async (req, res) => {
  await db.query('DELETE FROM marks WHERE id = ?', [req.params.id]);
  res.json({ message: 'Mark deleted' });
});

// ══════════════════════════════════════════════════════
//  SUBJECTS ROUTES
// ══════════════════════════════════════════════════════

app.get('/api/subjects', requireAuth, async (req, res) => {
  const [rows] = await db.query('SELECT * FROM subjects ORDER BY name');
  res.json(rows);
});

// ══════════════════════════════════════════════════════
//  STUDENTS ROUTES
// ══════════════════════════════════════════════════════

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
//  PDF REPORT CARD (existing)
// ══════════════════════════════════════════════════════
const PDFDocument = require('pdfkit');

app.get('/api/report-card', requireAuth, async (req, res) => {
  try {
    const studentId = req.user.student_id;
    const [studentRows] = await db.query(
      `SELECT u.name, u.email, s.student_number, s.grade_level
       FROM users u JOIN students s ON s.user_id = u.id
       WHERE u.id = ?`, [req.user.id]
    );
    if (!studentRows.length) return res.status(404).json({ error: 'Student not found' });
    const student = studentRows[0];
    const [marks] = await db.query(
      `SELECT m.*, s.name AS subject FROM marks m
       JOIN subjects s ON m.subject_id = s.id
       WHERE m.student_id = ? ORDER BY s.name, m.term`, [studentId]
    );
    const doc = new PDFDocument({ margin: 50 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="report-card-${student.student_number}.pdf"`);
    doc.pipe(res);
    doc.rect(0, 0, 612, 120).fill('#060910');
    doc.fillColor('#00e5ff').font('Helvetica-Bold').fontSize(24)
       .text('STUDENT REPORT CARD', 50, 35, { align: 'center' });
    doc.fillColor('#7a8499').font('Helvetica').fontSize(11)
       .text('Student Management System — School', 50, 65, { align: 'center' });
    doc.fillColor('#e8eaf0').fontSize(10)
       .text(`Generated: ${new Date().toLocaleDateString('en-ZA')}`, 50, 85, { align: 'center' });
    doc.moveDown(3);
    doc.rect(50, 135, 512, 80).fill('#0c1120').stroke('#1a56db');
    doc.fillColor('#00e5ff').font('Helvetica-Bold').fontSize(11)
       .text('STUDENT INFORMATION', 65, 148);
    doc.fillColor('#e8eaf0').font('Helvetica').fontSize(10);
    doc.text(`Name: ${student.name}`, 65, 168);
    doc.text(`Student No: ${student.student_number}`, 65, 183);
    doc.text(`Grade: ${student.grade_level}`, 300, 168);
    doc.text(`Email: ${student.email}`, 300, 183);
    doc.moveDown(2);
    let y = 235;
    doc.rect(50, y, 512, 25).fill('#1a56db');
    doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(9);
    doc.text('SUBJECT', 60, y + 8);
    doc.text('TERM', 220, y + 8);
    doc.text('MARK', 300, y + 8);
    doc.text('TOTAL', 360, y + 8);
    doc.text('%', 420, y + 8);
    doc.text('GRADE', 470, y + 8);
    y += 25;
    let totalPct = 0;
    let count = 0;
    marks.forEach((m, i) => {
      const pct = Math.round((m.mark / m.total) * 100);
      totalPct += pct;
      count++;
      const bg = i % 2 === 0 ? '#0f1826' : '#0c1120';
      doc.rect(50, y, 512, 22).fill(bg);
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
      if (y > 700) { doc.addPage(); y = 50; }
    });
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

// ══════════════════════════════════════════════════════
//  FULL REPORT CARD ROUTES (terms, attendance, conduct)
// ══════════════════════════════════════════════════════

// GET all terms
app.get('/api/terms', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM terms ORDER BY year DESC, id DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch terms' });
  }
});

// POST create term (teacher only)
app.post('/api/terms', requireTeacher, async (req, res) => {
  const { name, year, start_date, end_date } = req.body;
  if (!name || !year || !start_date || !end_date)
    return res.status(400).json({ error: 'All fields required' });
  try {
    await db.query(
      'INSERT INTO terms (name, year, start_date, end_date) VALUES (?, ?, ?, ?)',
      [name, year, start_date, end_date]
    );
    res.status(201).json({ message: 'Term created' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create term' });
  }
});

// GET full report card for a student for a term
app.get('/api/report-cards/:studentId/:termId', requireTeacher, async (req, res) => {
  const { studentId, termId } = req.params;
  try {
    const [students] = await db.query(
      `SELECT s.id, u.name AS first_name, '' AS last_name, s.grade_level AS grade,
              s.student_number AS admission_number, s.student_number AS class_name
       FROM students s JOIN users u ON s.user_id = u.id
       WHERE s.id = ?`, [studentId]
    );
    if (!students.length) return res.status(404).json({ message: 'Student not found' });

    const [terms] = await db.query('SELECT * FROM terms WHERE id = ?', [termId]);
    if (!terms.length) return res.status(404).json({ message: 'Term not found' });

    const [marks] = await db.query(
      `SELECT sub.name AS subject, sub.name AS code, m.mark, m.total AS max_mark,
              ROUND((m.mark / m.total) * 100, 1) AS percentage, NULL AS teacher_comment
       FROM marks m
       JOIN subjects sub ON m.subject_id = sub.id
       WHERE m.student_id = ? AND m.term = ?
       ORDER BY sub.name`,
      [studentId, terms[0].name]
    );

    const average = marks.length
      ? (marks.reduce((sum, m) => sum + parseFloat(m.percentage), 0) / marks.length).toFixed(1)
      : 0;

    const [attendance] = await db.query(
      'SELECT * FROM attendance WHERE student_id = ? AND term_id = ?',
      [studentId, termId]
    );

    const [conduct] = await db.query(
      'SELECT * FROM conduct WHERE student_id = ? AND term_id = ?',
      [studentId, termId]
    );

    res.json({
      student: students[0],
      term: terms[0],
      marks,
      average: parseFloat(average),
      symbol: getSymbol(average),
      attendance: attendance[0] || null,
      conduct: conduct[0] || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST save attendance
app.post('/api/attendance', requireTeacher, async (req, res) => {
  const { student_id, term_id, days_present, days_absent, days_late } = req.body;
  try {
    await db.query(
      `INSERT INTO attendance (student_id, term_id, days_present, days_absent, days_late)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE days_present = VALUES(days_present),
                               days_absent = VALUES(days_absent),
                               days_late = VALUES(days_late)`,
      [student_id, term_id, days_present, days_absent, days_late]
    );
    res.json({ message: 'Attendance saved' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save attendance' });
  }
});

// POST save conduct
app.post('/api/conduct', requireTeacher, async (req, res) => {
  const { student_id, term_id, rating, class_teacher_comment, principal_comment } = req.body;
  try {
    await db.query(
      `INSERT INTO conduct (student_id, term_id, rating, class_teacher_comment, principal_comment)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE rating = VALUES(rating),
                               class_teacher_comment = VALUES(class_teacher_comment),
                               principal_comment = VALUES(principal_comment)`,
      [student_id, term_id, rating, class_teacher_comment, principal_comment]
    );
    res.json({ message: 'Conduct saved' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save conduct' });
  }
});

// Helper: SA achievement levels
function getSymbol(avg) {
  if (avg >= 80) return { level: 7, label: 'Outstanding Achievement' };
  if (avg >= 70) return { level: 6, label: 'Meritorious Achievement' };
  if (avg >= 60) return { level: 5, label: 'Substantial Achievement' };
  if (avg >= 50) return { level: 4, label: 'Adequate Achievement' };
  if (avg >= 40) return { level: 3, label: 'Moderate Achievement' };
  if (avg >= 30) return { level: 2, label: 'Elementary Achievement' };
  return { level: 1, label: 'Not Achieved' };
}

// ============================================
// ATTENDANCE ROUTES
// Paste these into your server.js before the PAGE ROUTES section
// ============================================

// GET all classes for the logged-in teacher
app.get('/api/classes', requireTeacher, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM classes WHERE teacher_id = ? ORDER BY name',
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch classes' });
  }
});

// GET all students in a class
app.get('/api/classes/:classId/students', requireTeacher, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT s.id, u.name, s.student_number, s.grade_level
       FROM class_students cs
       JOIN students s ON cs.student_id = s.id
       JOIN users u ON s.user_id = u.id
       WHERE cs.class_id = ?
       ORDER BY u.name`,
      [req.params.classId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch students' });
  }
});

// GET attendance for a class on a specific date
app.get('/api/daily-attendance/:classId/:date', requireTeacher, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT da.student_id, da.status, da.note, u.name
       FROM daily_attendance da
       JOIN students s ON da.student_id = s.id
       JOIN users u ON s.user_id = u.id
       WHERE da.class_id = ? AND da.date = ?`,
      [req.params.classId, req.params.date]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});

// POST save attendance for a whole class for a date
app.post('/api/daily-attendance', requireTeacher, async (req, res) => {
  const { class_id, date, records } = req.body;
  if (!class_id || !date || !records || !records.length)
    return res.status(400).json({ error: 'Missing required fields' });
  try {
    for (const r of records) {
      await db.query(
        `INSERT INTO daily_attendance (student_id, class_id, date, status, marked_by, note)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE status = VALUES(status), note = VALUES(note), marked_by = VALUES(marked_by)`,
        [r.student_id, class_id, date, r.status, req.user.id, r.note || null]
      );
    }
    // Auto-update term attendance totals
    for (const r of records) {
      const [termRows] = await db.query(
        `SELECT t.id FROM terms t
         WHERE ? BETWEEN t.start_date AND t.end_date LIMIT 1`,
        [date]
      );
      if (termRows.length) {
        const termId = termRows[0].id;
        const [present] = await db.query(
          `SELECT COUNT(*) AS cnt FROM daily_attendance
           WHERE student_id = ? AND class_id = ? AND status = 'present'
           AND date BETWEEN (SELECT start_date FROM terms WHERE id = ?)
                        AND (SELECT end_date FROM terms WHERE id = ?)`,
          [r.student_id, class_id, termId, termId]
        );
        const [absent] = await db.query(
          `SELECT COUNT(*) AS cnt FROM daily_attendance
           WHERE student_id = ? AND class_id = ? AND status = 'absent'
           AND date BETWEEN (SELECT start_date FROM terms WHERE id = ?)
                        AND (SELECT end_date FROM terms WHERE id = ?)`,
          [r.student_id, class_id, termId, termId]
        );
        const [late] = await db.query(
          `SELECT COUNT(*) AS cnt FROM daily_attendance
           WHERE student_id = ? AND class_id = ? AND status = 'late'
           AND date BETWEEN (SELECT start_date FROM terms WHERE id = ?)
                        AND (SELECT end_date FROM terms WHERE id = ?)`,
          [r.student_id, class_id, termId, termId]
        );
        await db.query(
          `INSERT INTO attendance (student_id, term_id, days_present, days_absent, days_late)
           VALUES (?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE days_present = VALUES(days_present),
                                   days_absent = VALUES(days_absent),
                                   days_late = VALUES(days_late)`,
          [r.student_id, termId, present[0].cnt, absent[0].cnt, late[0].cnt]
        );
      }
    }
    res.json({ message: 'Attendance saved successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save attendance' });
  }
});

// GET attendance summary for a class for a term
app.get('/api/attendance-summary/:classId/:termId', requireTeacher, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT u.name, s.id AS student_id, s.student_number,
              SUM(da.status = 'present') AS days_present,
              SUM(da.status = 'absent')  AS days_absent,
              SUM(da.status = 'late')    AS days_late,
              COUNT(da.id)               AS total_days
       FROM class_students cs
       JOIN students s ON cs.student_id = s.id
       JOIN users u ON s.user_id = u.id
       LEFT JOIN daily_attendance da ON da.student_id = s.id
         AND da.class_id = cs.class_id
         AND da.date BETWEEN (SELECT start_date FROM terms WHERE id = ?)
                         AND (SELECT end_date FROM terms WHERE id = ?)
       WHERE cs.class_id = ?
       GROUP BY s.id, u.name, s.student_number
       ORDER BY u.name`,
      [req.params.termId, req.params.termId, req.params.classId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch summary' });
  }
});

// GET add student to class
app.post('/api/classes/:classId/students', requireTeacher, async (req, res) => {
  const { student_id } = req.body;
  try {
    await db.query(
      'INSERT IGNORE INTO class_students (class_id, student_id) VALUES (?, ?)',
      [req.params.classId, student_id]
    );
    res.json({ message: 'Student added to class' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add student' });
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
app.get('/report-card-view', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'report_card.html'));
});
app.get('/attendance', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'attendance.html'));
});
// ── START SERVER ──────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Student Management System running at http://localhost:${PORT}`);
});
