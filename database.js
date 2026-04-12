const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || "postgresql://chilex_db_user:6KQ1sbMiYxjyssxpvBTpihImutZsFzsN@dpg-d7dkr11j2pic73flt38g-a.ohio-postgres.render.com/chilex_db",
    ssl: {
        rejectUnauthorized: false
    }
});

// PostgreSQL wrapper with SQLite-compatible API
const db = {
    run(sql, params = []) {
        return new Promise((resolve, reject) => {
            pool.query(sql, params)
                .then(result => resolve({ changes: result.rowCount }))
                .catch(err => reject(err));
        });
    },
    
    get(sql, params = []) {
        return new Promise((resolve, reject) => {
            pool.query(sql, params)
                .then(result => resolve(result.rows[0] || null))
                .catch(err => reject(err));
        });
    },
    
    all(sql, params = []) {
        return new Promise((resolve, reject) => {
            pool.query(sql, params)
                .then(result => resolve(result.rows))
                .catch(err => reject(err));
        });
    },
    
    // Also expose async/await versions for direct PostgreSQL access
    query: (...args) => pool.query(...args),
    pool: pool
};

pool.connect()
    .then(() => console.log("✅ Connected to PostgreSQL"))
    .catch(err => console.error("❌ PostgreSQL connection error:", err));

module.exports = db;