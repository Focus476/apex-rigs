const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = reqire('bcrypt.js');
const cookieParser = require('cookie-parser');


const app = express();
const PORT = 3000;

//middleware 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


//initialize the database
const db = new sqlite3.Database('./apex.db', (err) => {
    if (err) console.error('Database opening error; ' + err.message);
    else console.log('connected to the SQLite database.');
});

//create users table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT
)`);


//register route
app.post('/api/register', async (req, res) => {
    const {username, email, password} = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
            [username, email, hashedPassword],
            function(err) {
                if (err) {
                    return res.status(400).json({ error: 'User already exists' });
                }
                res.json({ message: 'User registered successfully',});
            }
        );
    } catch {
        res.status(500).json({ error: 'Server error during registration' });
    }
});


//login route(cookies)
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        // Set an HTTP-only cookie for session tracking
        res.cookie('userSession', user.username, { 
            maxAge: 900000, 
            httpOnly: true 
        });
        res.json({ message: `Welcome back, ${user.username}!` });
    });
});

// Check Session Route (Reads Cookie & Database)
app.get('/api/session', (req, res) => {
    const userSession = req.cookies.userSession;
    if (userSession) {
        res.json({ loggedIn: true, username: userSession });
    } else {
        res.json({ loggedIn: false });
    }
});

// Logout Route (Clears Cookie)
app.post('/api/logout', (req, res) => {
    res.clearCookie('userSession');
    res.json({ message: 'Logged out successfully.' });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});