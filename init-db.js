const pool = require('./database');

async function init() {
    try {
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

            CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL PRIMARY KEY,
                license_key TEXT UNIQUE,
                status TEXT DEFAULT 'active',
                machine_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                subject TEXT,
                exam_body TEXT,
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log("✅ Tables created successfully");
        process.exit();
    } catch (err) {
        console.error("❌ Error creating tables:", err);
        process.exit(1);
    }
}

init();