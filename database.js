const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const argon2 = require('argon2');

const dbPath = path.resolve(__dirname, 'chilex_admin.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Could not connect to database", err);
    } else {
        console.log("Connected to SQLite database");
    }
});

// Initialize Schema
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS administrators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            full_name TEXT,
            phone TEXT,
            avatar_url TEXT,
            role TEXT DEFAULT 'admin', -- super_admin, admin
            permissions TEXT -- JSON string of permissions
        )
    `);

    // Migration for existing tables
    ['full_name', 'phone', 'avatar_url', 'role', 'permissions'].forEach(col => {
        db.run(`ALTER TABLE administrators ADD COLUMN ${col} TEXT`, (err) => { /* ignore */ });
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            admin_username TEXT,
            action TEXT,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);


    db.run(`
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE,
            status TEXT DEFAULT 'active', -- active, used, expired
            machine_id TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            exam_body TEXT, -- JAMB, WAEC, NECO
            year TEXT,
            question_text TEXT,
            option_a TEXT,
            option_b TEXT,
            option_c TEXT,
            option_d TEXT,
            correct_option TEXT,
            question_image TEXT,
            option_a_image TEXT,
            option_b_image TEXT,
            option_c_image TEXT,
            option_d_image TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Migration: Add image columns to existing questions table
    ['question_image', 'option_a_image', 'option_b_image', 'option_c_image', 'option_d_image'].forEach(col => {
        db.run(`ALTER TABLE questions ADD COLUMN ${col} TEXT`, (err) => { /* ignore if exists */ });
    });

    // Create default admin if not exists: admin / admin123
    db.get("SELECT * FROM administrators WHERE username = ?", ["admin"], async (err, row) => {
        if (!row) {
            try {
                const hash = await argon2.hash("admin123");
                db.run("INSERT INTO administrators (username, password_hash, role, permissions) VALUES (?, ?, ?, ?)",
                    ["admin", hash, "super_admin", JSON.stringify(['stats', 'licenses', 'questions', 'users', 'activity'])]);
                console.log("Default super-admin account created.");
            } catch (error) {
                console.error("Failed to create default admin", error);
            }
        } else {
            // Ensure first admin is super_admin if not already set (for migration)
            if (row.username === 'admin' && row.role !== 'super_admin') {
                db.run("UPDATE administrators SET role = 'super_admin', permissions = ? WHERE id = ?",
                    [JSON.stringify(['stats', 'licenses', 'questions', 'users', 'activity']), row.id]);
            }
        }
    });

    // Create a default license if none exist
    db.get("SELECT COUNT(*) as count FROM licenses", [], (err, row) => {
        if (row.count === 0) {
            const crypto = require('crypto');
            const signature = crypto.randomBytes(6).toString('hex').toUpperCase();
            const key = `CHX-${signature.slice(0, 4)}-${signature.slice(4, 8)}-${signature.slice(8, 12)}`;
            db.run("INSERT INTO licenses (license_key) VALUES (?)", [key]);
            console.log("Default license created:", key);
        }
    });
});

module.exports = db;
