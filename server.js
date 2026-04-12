const express = require('express');
const cors = require('cors');
const db = require('./database'); // your postgres pool
const argon2 = require('argon2');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ LOGIN ROUTE
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await db.query(
            'SELECT * FROM administrators WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = result.rows[0];

        const valid = await argon2.verify(user.password_hash, password);

        if (!valid) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        res.json({
            token: 'dummy-token',
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/', (req, res) => {
    res.send('API is running...');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));