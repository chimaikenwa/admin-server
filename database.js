const { Pool } = require('pg');

const pool = new Pool({
    connectionString: "postgresql://chilex_db_user:6KQ1sbMiYxjyssxpvBTpihImutZsFzsN@dpg-d7dkr11j2pic73flt38g-a.ohio-postgres.render.com/chilex_db",
    ssl: {
        rejectUnauthorized: false
    }
});

pool.connect()
    .then(() => console.log("✅ Connected to PostgreSQL"))
    .catch(err => console.error("❌ PostgreSQL connection error:", err));

module.exports = pool;