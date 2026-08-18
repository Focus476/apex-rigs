const express = require('express');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Setup LowDB (Pure JS Database stored in db.json)
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const defaultData = { users: [] };
const db = new Low(adapter, defaultData);

async function initDB() {
    await db.read();
    db.data ||= defaultData;
    await db.write();
}
initDB();

// Explicit Root Route to serve frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register Route
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    await db.read();
    const existingUser = db.data.users.find(u => u.email === email || u.username === username);
    
    if (existingUser) {
        return res.status(400).json({ error: 'Username or email already exists.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.data.users.push({
            id: Date.now(),
            username,
            email,
            password: hashedPassword
        });
        await db.write();
        
        res.json({ message: 'User registered successfully!' });
    } catch {
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// Login Route (Sets a Cookie)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    await db.read();
    const user = db.data.users.find(u => u.email === email);
    
    if (!user) {
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

// Check Session Route
app.get('/api/session', async (req, res) => {
    const userSession = req.cookies.userSession;
    if (userSession) {
        res.json({ loggedIn: true, username: userSession });
    } else {
        res.json({ loggedIn: false });
    }
});

// Logout Route
app.post('/api/logout', (req, res) => {
    res.clearCookie('userSession');
    res.json({ message: 'Logged out successfully.' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});