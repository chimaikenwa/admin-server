const { Pool } = require('pg');

console.log("DATABASE_URL:", process.env.DATABASE_URL ? "set" : "NOT SET");

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || "postgresql://postgres:postgres@localhost:5432/chilex",
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Convert PostgreSQL $1, $2 to ? for backward compatibility
function convertParams(sql, params) {
    if (!params || params.length === 0) return { sql, params };
    // If already using $1, $2 syntax, return as-is
    if (sql.includes('$1')) return { sql, params };
    // Convert ? to $1, $2, ...
    let newSql = sql;
    for (let i = 0; i < params.length; i++) {
        newSql = newSql.replace('?', '$' + (i + 1));
    }
    return { sql: newSql, params };
}

// PostgreSQL wrapper - supports both async/await AND callback style
const db = {
    // Async/await style (PostgreSQL native)
    async query(sql, params) {
        const { sql: converted, params: convertedParams } = convertParams(sql, params);
        console.log("QUERY:", converted, convertedParams);
        return pool.query(converted, convertedParams);
    },
    
    // Callback style (backward compatible with old SQLite code)
    run(sql, params = [], callback) {
        const { sql: converted, params: convertedParams } = convertParams(sql, params);
        pool.query(converted, convertedParams)
            .then(result => callback(null, { changes: result.rowCount }))
            .catch(err => callback(err));
    },
    
    get(sql, params = [], callback) {
        const { sql: converted, params: convertedParams } = convertParams(sql, params);
        pool.query(converted, convertedParams)
            .then(result => callback(null, result.rows[0] || null))
            .catch(err => callback(err));
    },
    
    all(sql, params = [], callback) {
        const { sql: converted, params: convertedParams } = convertParams(sql, params);
        pool.query(converted, convertedParams)
            .then(result => callback(null, result.rows))
            .catch(err => callback(err));
    },
    
    // Expose pool for direct access
    pool: pool
};

pool.connect()
    .then(() => console.log("✅ Connected to PostgreSQL"))
    .catch(err => console.error("❌ PostgreSQL connection error:", err));

module.exports = db;