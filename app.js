const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./database.db');

// Konfigurasi Express & EJS
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'kunci-rahasia-teknik-ai',
    resave: false,
    saveUninitialized: true
}));
//PUBLIK IMAgES
app.use(express.static('public'));

// Buat Tabel User di Database jika belum ada
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);
});

// Middleware Cek Login
function checkAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

// --- ROUTE / HALAMAN ---

// Halaman Utama (Doproteksi Login)
app.get('/', checkAuth, (req, res) => {
    res.render('index', { user: req.session.username });
});

// Halaman Register
app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], (err) => {
        if (err) {
            return res.render('register', { error: 'Username sudah digunakan!' });
        }
        res.redirect('/login');
    });
});

// Halaman Login
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.render('login', { error: 'Username atau password salah!' });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        res.redirect('/');
    });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Jalankan Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});