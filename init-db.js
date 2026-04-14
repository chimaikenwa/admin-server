const pool = require('./database');

async function init() {
  console.log("🚀 Starting database initialization...");
  try {
    // We combine everything into one single call to save connection time
    await pool.query(`
      CREATE TABLE IF NOT EXISTS administrators (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        full_name TEXT,
        role TEXT DEFAULT 'admin'
      );

      CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER,
        action TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      INSERT INTO administrators (username, password_hash, full_name, role)
      VALUES ('admin', 'admin123@', 'System Admin', 'admin')
      ON CONFLICT (username) DO NOTHING;
    `);

    console.log("✅ Database is ready!");
  } catch (err) {
    console.error("❌ Critical Init Error:", err.message);
    // Don't exit with 1 if it's just a "table already exists" warning
    if (err.message.includes("already exists")) {
        console.log("⚠️ Tables already exist, skipping...");
    } else {
        process.exit(1); 
    }
  } finally {
    await pool.end();
    console.log("💤 Connection closed. Starting server...");
    process.exit(0); 
  }
}

init();