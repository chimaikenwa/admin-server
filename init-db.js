const { Pool } = require('pg');
const argon2 = require('argon2');

// PostgreSQL connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || "postgresql://postgres:postgres@localhost:5432/chilex",
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function init() {
    console.log("🚀 Starting database initialization...");

    try {
        // Create administrators table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS administrators (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                phone TEXT,
                role TEXT DEFAULT 'admin',
                permissions JSONB DEFAULT '[]',
                avatar_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("✅ administrators table created");

        // Create activity_logs table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS activity_logs (
                id SERIAL PRIMARY KEY,
                admin_id INTEGER REFERENCES administrators(id),
                admin_username TEXT,
                action TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("✅ activity_logs table created");

        // Create licenses table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL PRIMARY KEY,
                license_key TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'active',
                machine_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("✅ licenses table created");

        // Create questions table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                subject TEXT NOT NULL,
                exam_body TEXT,
                year TEXT,
                question_text TEXT NOT NULL,
                option_a TEXT,
                option_b TEXT,
                option_c TEXT,
                option_d TEXT,
                correct_option INTEGER DEFAULT 0,
                question_image TEXT,
                option_a_image TEXT,
                option_b_image TEXT,
                option_c_image TEXT,
                option_d_image TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("✅ questions table created");

        // Create default admin user with argon2 hash
        const hash = await argon2.hash('admin123', { type: argon2.argon2id });
        await pool.query(`
            INSERT INTO administrators (username, password_hash, full_name, role, permissions)
            VALUES ('admin', $1, 'Super Admin', 'super_admin', '["stats","licenses","questions","activity","users"]')
            ON CONFLICT (username) DO NOTHING;
        `, [hash]);
        console.log("✅ Default admin user created (username: admin, password: admin123)");

        console.log("✅ Database initialization complete!");

    } catch (err) {
        console.error("❌ Database init error:", err.message);
    }
}

// Run if called directly
if (require.main === module) {
    init().then(() => process.exit(0)).catch(err => process.exit(1));
}

module.exports = { pool, init };