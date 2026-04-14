const pool = require('./database');

async function init() {
  try {
    console.log("Starting database initialization...");

    // 1. Create Tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS administrators (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        full_name TEXT,
        phone TEXT,
        avatar_url TEXT,
        role TEXT DEFAULT 'admin',
        permissions TEXT
      );

      CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER,
        admin_username TEXT,
        action TEXT,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 2. Insert Admin User
    await pool.query(`
      INSERT INTO administrators (username, password_hash, full_name, role)
      VALUES ('admin', 'admin123@', 'System Admin', 'admin')
      ON CONFLICT (username) DO NOTHING;
    `);

    console.log("✅ Tables created and admin user verified successfully");
  } catch (err) {
    console.error("❌ Error initializing database:", err);
    process.exit(1); 
  } finally {
    await pool.end(); // Closes connection so the script can finish
    process.exit(0);  // Signals success to Render
  }
}

init();