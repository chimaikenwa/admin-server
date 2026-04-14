const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const db = require('./database');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');

const app = express();

// Allow local development origins
app.use(cors({
    origin: [
        'http://localhost:4000',
        'http://127.0.0.1:4000',
        'null' // file:// origins appear as 'null'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.options(/.*/, cors()); // Pre-flight for all routes (Express 5 compatible)

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const upload = multer({ dest: path.join(__dirname, 'uploads') });
const SECRET_KEY = process.env.SECRET_KEY || 'chilex_super_secret_override_me';

// Utility: Log Activity
const logActivity = async (adminId, username, action, details) => {
    await db.run("INSERT INTO activity_logs (admin_id, admin_username, action, details) VALUES ($1, $2, $3, $4)",
        [adminId, username, action, details]);
};

// Utility: Verify Admin Token
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = await db.get("SELECT id, username, role, permissions FROM administrators WHERE id = $1", [decoded.id]);
        if (!user) return res.sendStatus(401);
        req.user = {
            ...user,
            permissions: user.permissions ? JSON.parse(user.permissions) : []
        };
        next();
    } catch (err) {
        return res.sendStatus(403);
    }
};

// Middleware: Check Permission
const checkPermission = (perm) => (req, res, next) => {
    if (req.user.role === 'super_admin' || req.user.permissions.includes(perm)) {
        next();
    } else {
        res.status(403).json({ error: 'Permission denied' });
    }
};

const superOnly = (req, res, next) => {
    if (req.user.role === 'super_admin') next();
    else res.status(403).json({ error: 'Super Admin only' });
};

/* --- ADMIN AUTH ROUTES --- */
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    console.log("Login attempt for:", username);
    
    try {
        const result = await db.query("SELECT * FROM administrators WHERE username = $1", [username]);
        const row = result.rows[0];
        
        if (!row) {
            console.log("User not found:", username);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (bcrypt.compareSync(password, row.password_hash)) {
            const token = jwt.sign({ id: row.id, username: row.username }, SECRET_KEY, { expiresIn: '24h' });
            console.log("Login success:", username);
            res.json({ token });
        } else {
            console.log("Wrong password for:", username);
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error("LOGIN ERROR:", error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

/* --- LICENSE ROUTES (FOR DESKTOP APP) --- */
app.post('/api/licenses/validate', async (req, res) => {
    const { license_key, machine_id } = req.body;
    try {
        const result = await db.query("SELECT * FROM licenses WHERE license_key = $1", [license_key]);
        const row = result.rows[0];
        
        if (!row) return res.status(404).json({ valid: false, error: 'License not found' });
        if (row.status !== 'active') return res.status(403).json({ valid: false, error: `License is ${row.status}` });

        // Lock to machine if first use
        if (!row.machine_id && machine_id) {
            await db.query("UPDATE licenses SET machine_id = $1 WHERE id = $2", [machine_id, row.id]);
            return res.json({ valid: true, message: 'License verified and bound to this PC.' });
        } else if (row.machine_id === machine_id || !machine_id) {
            return res.json({ valid: true, message: 'License verified.' });
        } else {
            return res.status(403).json({ valid: false, error: 'License is bound to another PC.' });
        }
    } catch (error) {
        console.error("LICENSE VALIDATE ERROR:", error);
        res.status(500).json({ error: error.message });
    }
});

/* --- ADMIN API ROUTES --- */
app.get('/api/admin/stats', authenticateToken, checkPermission('stats'), async (req, res) => {
    try {
        const lr = await db.query("SELECT COUNT(*) as total_licenses FROM licenses");
        const qr = await db.query("SELECT COUNT(*) as total_questions FROM questions");
        const ar = await db.query("SELECT COUNT(*) as active_licenses FROM licenses WHERE status = 'active'");
        const ur = await db.query("SELECT COUNT(*) as used_licenses FROM licenses WHERE status = 'used'");
        
        res.json({
            total_licenses: parseInt(lr.rows[0]?.total_licenses) || 0,
            total_questions: parseInt(qr.rows[0]?.total_questions) || 0,
            active_licenses: parseInt(ar.rows[0]?.active_licenses) || 0,
            used_licenses: parseInt(ur.rows[0]?.used_licenses) || 0
        });
    } catch (error) {
        console.error("STATS ERROR:", error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/licenses', authenticateToken, checkPermission('licenses'), async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM licenses ORDER BY id DESC");
        res.json({ licenses: result.rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/licenses/generate', authenticateToken, checkPermission('licenses'), (req, res) => {
    const { amount = 1 } = req.body;
    const generated = [];
    for (let i = 0; i < amount; i++) {
        const signature = crypto.randomBytes(6).toString('hex').toUpperCase();
        const key = `CHX-${signature.slice(0, 4)}-${signature.slice(4, 8)}-${signature.slice(8, 12)}`;
        db.run("INSERT INTO licenses (license_key) VALUES (?)", [key]);
        generated.push(key);
    }
    logActivity(req.user.id, req.user.username, 'GENERATE_LICENSES', `Generated ${amount} licenses`);
    res.json({ generated, message: `Successfully generated ${amount} licenses.` });
});

// Revoke a license
app.patch('/api/admin/licenses/:id/revoke', authenticateToken, checkPermission('licenses'), (req, res) => {
    db.run("UPDATE licenses SET status='revoked', machine_id=NULL WHERE id=?", [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'REVOKE_LICENSE', `Revoked license ID: ${req.params.id}`);
        res.json({ message: 'License revoked.' });
    });
});

// Reset a license (make active again)
app.patch('/api/admin/licenses/:id/reset', authenticateToken, checkPermission('licenses'), (req, res) => {
    db.run("UPDATE licenses SET status='active', machine_id=NULL WHERE id=?", [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'RESET_LICENSE', `Reset license ID: ${req.params.id}`);
        res.json({ message: 'License reset to active.' });
    });
});

// Delete a license
app.delete('/api/admin/licenses/:id', authenticateToken, checkPermission('licenses'), (req, res) => {
    db.run("DELETE FROM licenses WHERE id=?", [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'DELETE_LICENSE', `Deleted license ID: ${req.params.id}`);
        res.json({ message: 'License deleted.' });
    });
});

app.get('/api/questions/sync', (req, res) => {
    // End user fetches questions
    db.all("SELECT * FROM questions", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ questions: rows });
    });
});

/* --- ADMIN QUESTION MANAGEMENT --- */
app.get('/api/admin/questions', authenticateToken, checkPermission('questions'), (req, res) => {
    const { page = 1, limit = 50, id, subject = '', exam_body = '', year = '', search = '' } = req.query;
    
    // If ID is provided, return only that question (ignore other filters)
    if (id) {
        db.get("SELECT * FROM questions WHERE id = ?", [id], (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ questions: row ? [row] : [] });
        });
        return;
    }
    
    const offset = (parseInt(page) - 1) * parseInt(limit);
    let where = [];
    let params = [];
    if (subject) { where.push("subject = ?"); params.push(subject); }
    if (exam_body) { where.push("exam_body = ?"); params.push(exam_body); }
    if (year) { where.push("year = ?"); params.push(year); }
    if (search) { where.push("question_text LIKE ?"); params.push(`%${search}%`); }
    const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';
    db.get(`SELECT COUNT(*) as total FROM questions ${clause}`, params, (err, countRow) => {
        db.all(`SELECT * FROM questions ${clause} ORDER BY id DESC LIMIT ? OFFSET ?`,
            [...params, parseInt(limit), offset], (err2, rows) => {
                if (err2) return res.status(500).json({ error: err2.message });
                res.json({ questions: rows, total: countRow?.total || 0, page: parseInt(page) });
            }
        );
    });
});

// Delete a single question (super_admin only)
app.delete('/api/admin/questions/:id', authenticateToken, superOnly, (req, res) => {
    db.run("DELETE FROM questions WHERE id=?", [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'DELETE_QUESTION', `Deleted question ID: ${req.params.id}`);
        res.json({ message: 'Question deleted.' });
    });
});

// Update a single question (admin and super_admin can edit)
app.put('/api/admin/questions/:id', authenticateToken, checkPermission('questions'), (req, res) => {
    const { subject, exam_body, year, question_text, option_a, option_b, option_c, option_d, correct_option, question_image, option_a_image, option_b_image, option_c_image, option_d_image } = req.body;
    db.run(`
        UPDATE questions SET 
            subject = COALESCE(?, subject),
            exam_body = COALESCE(?, exam_body),
            year = COALESCE(?, year),
            question_text = COALESCE(?, question_text),
            option_a = COALESCE(?, option_a),
            option_b = COALESCE(?, option_b),
            option_c = COALESCE(?, option_c),
            option_d = COALESCE(?, option_d),
            correct_option = COALESCE(?, correct_option),
            question_image = COALESCE(?, question_image),
            option_a_image = COALESCE(?, option_a_image),
            option_b_image = COALESCE(?, option_b_image),
            option_c_image = COALESCE(?, option_c_image),
            option_d_image = COALESCE(?, option_d_image)
        WHERE id = ?
    `, [subject, exam_body, year, question_text, option_a, option_b, option_c, option_d, correct_option, question_image, option_a_image, option_b_image, option_c_image, option_d_image, req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'UPDATE_QUESTION', `Updated question ID: ${req.params.id}`);
        res.json({ message: 'Question updated successfully.' });
    });
});

// Bulk update questions - change exam_body and/or year (super_admin only)
app.patch('/api/admin/questions/bulk', authenticateToken, superOnly, (req, res) => {
    const { ids, exam_body, year } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'No question IDs provided' });
    }
    const placeholders = ids.map(() => '?').join(',');
    let sql = 'UPDATE questions SET ';
    const params = [];
    if (exam_body) { sql += 'exam_body = ?, '; params.push(exam_body); }
    if (year) { sql += 'year = ?, '; params.push(year); }
    if (params.length === 0) return res.status(400).json({ error: 'No fields to update' });
    sql += ' WHERE id IN (' + placeholders + ')';
    db.run(sql, [...params, ...ids], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'BULK_UPDATE_QUESTIONS', `Bulk updated ${this.changes} questions`);
        res.json({ message: `Successfully updated ${this.changes} questions.`, updated_count: this.changes });
    });
});

// Bulk delete questions (super_admin only)
app.delete('/api/admin/questions/bulk', authenticateToken, superOnly, (req, res) => {
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'No question IDs provided' });
    }
    const placeholders = ids.map(() => '?').join(',');
    db.run(`DELETE FROM questions WHERE id IN (${placeholders})`, ids, function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'BULK_DELETE_QUESTIONS', `Bulk deleted ${this.changes} questions`);
        res.json({ message: `Successfully deleted ${this.changes} questions.`, deleted_count: this.changes });
    });
});

// Upload image for question or option
const questionImageUpload = multer({
    dest: path.join(__dirname, 'uploads', 'questions'),
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const ext = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mime = allowedTypes.test(file.mimetype);
        if (ext || mime) cb(null, true);
        else cb(new Error('Only image files are allowed'));
    }
});

app.post('/api/admin/questions/image', authenticateToken, checkPermission('questions'), questionImageUpload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No image uploaded' });
    const imageUrl = `/uploads/questions/${req.file.filename}`;
    res.json({ image_url: imageUrl, filename: req.file.filename });
});

// Update user (super_admin only)
app.patch('/api/admin/users/:id', authenticateToken, superOnly, async (req, res) => {
    const { username, full_name, phone, role, permissions, password } = req.body;
    if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot edit yourself' });
    
    if (password) {
        const hash = bcrypt.hashSync(password, 10);
        db.run(`
            UPDATE administrators SET 
                username = COALESCE(?, username),
                full_name = COALESCE(?, full_name),
                phone = COALESCE(?, phone),
                role = COALESCE(?, role),
                permissions = COALESCE(?, permissions),
                password_hash = ?
            WHERE id = ?
        `, [username, full_name, phone, role, permissions ? JSON.stringify(permissions) : null, hash, req.params.id], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            logActivity(req.user.id, req.user.username, 'UPDATE_USER', `Updated user ID: ${req.params.id} (with password)`);
            res.json({ message: 'User updated successfully.' });
        });
    } else {
        db.run(`
            UPDATE administrators SET 
                username = COALESCE(?, username),
                full_name = COALESCE(?, full_name),
                phone = COALESCE(?, phone),
                role = COALESCE(?, role),
                permissions = COALESCE(?, permissions)
            WHERE id = ?
        `, [username, full_name, phone, role, permissions ? JSON.stringify(permissions) : null, req.params.id], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            logActivity(req.user.id, req.user.username, 'UPDATE_USER', `Updated user ID: ${req.params.id}`);
            res.json({ message: 'User updated successfully.' });
        });
    }
});

// Add single question (admin and super_admin)
app.post('/api/admin/questions', authenticateToken, checkPermission('questions'), (req, res) => {
    const { subject, exam_body, year, question_text, option_a, option_b, option_c, option_d, correct_option, question_image, option_a_image, option_b_image, option_c_image, option_d_image } = req.body;
    if (!subject || !exam_body || !year || !question_text || !option_a || !option_b || !option_c || !option_d || correct_option === undefined) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    db.run(`
        INSERT INTO questions (subject, exam_body, year, question_text, option_a, option_b, option_c, option_d, correct_option, question_image, option_a_image, option_b_image, option_c_image, option_d_image)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [subject, exam_body, year, question_text, option_a, option_b, option_c, option_d, correct_option, question_image || null, option_a_image || null, option_b_image || null, option_c_image || null, option_d_image || null], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'ADD_QUESTION', `Added question ID: ${this.lastID}`);
        res.json({ message: 'Question added successfully.', id: this.lastID });
    });
});

// Delete all questions (bulk clear)
app.delete('/api/admin/questions', authenticateToken, checkPermission('questions'), (req, res) => {
    db.run("DELETE FROM questions", [], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'CLEAR_QUESTIONS', `Deleted all ${this.changes} questions`);
        res.json({ message: `Cleared ${this.changes} questions from the bank.` });
    });
});

// Get distinct subjects, exam bodies, and years for filters
app.get('/api/admin/questions/meta', authenticateToken, checkPermission('questions'), (req, res) => {
    const { subject, exam_body } = req.query;
    
    let subjectQuery = "SELECT DISTINCT subject FROM questions ORDER BY subject";
    let bodyQuery = "SELECT DISTINCT exam_body FROM questions ORDER BY exam_body";
    let yearQuery = "SELECT DISTINCT year FROM questions ORDER BY year DESC";
    let params = [];
    
    if (subject) {
        yearQuery = "SELECT DISTINCT year FROM questions WHERE subject = ? ORDER BY year DESC";
        params.push(subject);
    }
    
    db.all(subjectQuery, [], (e1, subjects) => {
        db.all(bodyQuery, [], (e2, bodies) => {
            db.all(yearQuery, params, (e3, years) => {
                res.json({
                    subjects: subjects.map(r => r.subject),
                    exam_bodies: bodies.map(r => r.exam_body),
                    years: years.map(r => r.year)
                });
            });
        });
    });
});

app.post('/api/admin/questions/upload', authenticateToken, checkPermission('questions'), upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const ext = path.extname(req.file.originalname).toLowerCase();
    let questions = [];

    const processQuestions = (results) => {
        const stmt = db.prepare(`
            INSERT INTO questions (subject, exam_body, year, question_text, option_a, option_b, option_c, option_d, correct_option)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        results.forEach(q => {
            stmt.run([
                q.subject || q.Subject,
                q.exam_body || q.ExamBody || q.Exam,
                q.year || q.Year,
                q.question_text || q.Question || q.Text,
                q.option_a || q.OptionA || q.A,
                q.option_b || q.OptionB || q.B,
                q.option_c || q.OptionC || q.C,
                q.option_d || q.OptionD || q.D,
                q.correct_option || q.CorrectOption || q.Answer
            ]);
        });
        stmt.finalize();
        fs.unlinkSync(req.file.path);
        logActivity(req.user.id, req.user.username, 'UPLOAD_QUESTIONS', `Imported ${results.length} questions from ${req.file.originalname}`);
        res.json({ message: `Successfully imported ${results.length} questions.` });
    };

    if (ext === '.csv') {
        fs.createReadStream(req.file.path).pipe(csv()).on('data', (data) => questions.push(data)).on('end', () => processQuestions(questions));
    } else if (ext === '.json') {
        const data = JSON.parse(fs.readFileSync(req.file.path, 'utf8'));
        processQuestions(Array.isArray(data) ? data : [data]);
    } else if (ext === '.txt') {
        const content = fs.readFileSync(req.file.path, 'utf8');
        const blocks = content.split('---');
        blocks.forEach(block => {
            const lines = block.trim().split('\n');
            const q = {};
            lines.forEach(line => {
                const [key, ...val] = line.split(':');
                const v = val.join(':').trim();
                if (key === 'Subject') q.subject = v;
                if (key === 'Exam') q.exam_body = v;
                if (key === 'Year') q.year = v;
                if (key === 'Q') q.question_text = v;
                if (key === 'A') q.option_a = v;
                if (key === 'B') q.option_b = v;
                if (key === 'C') q.option_c = v;
                if (key === 'D') q.option_d = v;
                if (key === 'ANS') q.correct_option = v;
            });
            if (q.question_text) questions.push(q);
        });
        processQuestions(questions);
    } else {
        res.status(400).json({ error: 'Unsupported format' });
    }
});

/* --- SUPER ADMIN MANAGEMENT --- */
app.get('/api/admin/users', authenticateToken, superOnly, (req, res) => {
    db.all("SELECT id, username, full_name, role, permissions FROM administrators", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows.map(r => ({ ...r, permissions: JSON.parse(r.permissions || '[]') })));
    });
});

app.post('/api/admin/users/create', authenticateToken, superOnly, async (req, res) => {
    const { username, password, full_name, role, permissions } = req.body;
    try {
        const hash = bcrypt.hashSync(password, 10);
        db.run("INSERT INTO administrators (username, password_hash, full_name, role, permissions) VALUES (?, ?, ?, ?, ?)",
            [username, hash, full_name, role, JSON.stringify(permissions)], function (err) {
                if (err) return res.status(400).json({ error: 'Username already exists' });
                logActivity(req.user.id, req.user.username, 'CREATE_USER', `Created admin user: ${username}`);
                res.json({ message: 'User created successfully' });
            });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', authenticateToken, superOnly, (req, res) => {
    if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    db.run("DELETE FROM administrators WHERE id = ?", [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        logActivity(req.user.id, req.user.username, 'DELETE_USER', `Deleted user ID: ${req.params.id}`);
        res.json({ message: 'User deleted' });
    });
});

app.get('/api/admin/activity', authenticateToken, (req, res) => {
    db.all(`
        SELECT al.*, a.full_name 
        FROM activity_logs al 
        LEFT JOIN administrators a ON al.admin_id = a.id 
        ORDER BY al.id DESC LIMIT 100`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        // Use full_name if available, otherwise fallback to username
        const logs = rows.map(l => ({
            ...l,
            display_name: l.full_name || l.admin_username || 'System'
        }));
        res.json(logs);
    });
});

/* --- ADMIN PROFILE MANAGEMENT --- */
app.get('/api/admin/profile', authenticateToken, (req, res) => {
    db.get(
        "SELECT id, username, full_name, phone, avatar_url, role, permissions FROM administrators WHERE id = ?",
        [req.user.id],
        (err, row) => {
            if (err || !row) return res.status(404).json({ error: 'User not found' });
            res.json({
                ...row,
                permissions: row.permissions ? JSON.parse(row.permissions) : []
            });
        }
    );
});

app.post('/api/admin/profile/update', authenticateToken, async (req, res) => {
    const { full_name, phone, password } = req.body;
    const adminId = parseInt(req.user.id);

    console.log(`Updating profile for admin ID: ${adminId}`, { full_name, phone });

    if (password) {
        const hash = bcrypt.hashSync(password, 10);
        db.run("UPDATE administrators SET full_name = ?, phone = ?, password_hash = ? WHERE id = ?",
            [full_name, phone, hash, adminId], function (err) {
                if (err) {
                    console.error("DB Update Error (Password):", err);
                    return res.status(500).json({ error: err.message });
                }
                console.log(`Profile + Password updated for ${adminId}. Changes: ${this.changes}`);
                res.json({ message: 'Profile and password updated successfully.' });
            });
    } else {
        db.run("UPDATE administrators SET full_name = ?, phone = ? WHERE id = ?",
            [full_name, phone, adminId], function (err) {
                if (err) {
                    console.error("DB Update Error:", err);
                    return res.status(500).json({ error: err.message });
                }
                console.log(`Profile updated for ${adminId}. Changes: ${this.changes}`);
                res.json({ message: 'Profile updated successfully.' });
            });
    }
});

app.post('/api/admin/profile/avatar', authenticateToken, upload.single('avatar'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No avatar uploaded' });

    const avatarUrl = `/uploads/${req.file.filename}`;
    db.run("UPDATE administrators SET avatar_url = ? WHERE id = ?", [avatarUrl, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Avatar updated successfully.', avatar_url: avatarUrl });
    });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Admin server running on port ${PORT}`);
});
