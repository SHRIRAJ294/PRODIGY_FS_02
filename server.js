const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

// Initialize Express app
const app = express();
const port = process.env.PORT || 5000;

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

// MySQL connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to database.');
});

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session.username) {
        return next();
    }
    res.redirect('/login');
}

// Routes
app.get('/', (req, res) => {
    res.render('index');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) throw err;
        db.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash], (err) => {
            if (err) throw err;
            res.redirect('/login');
        });
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            bcrypt.compare(password, results[0].password_hash, (err, isMatch) => {
                if (err) throw err;
                if (isMatch) {
                    req.session.username = username;
                    res.redirect('/employees');
                } else {
                    res.send('Invalid credentials <a href="/login">Try again</a>');
                }
            });
        } else {
            res.send('User not found <a href="/login">Try again</a>');
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) throw err;
        res.redirect('/login');
    });
});

// Employee Management Routes
app.get('/employees', isAuthenticated, (req, res) => {
    db.query('SELECT * FROM employees', (err, results) => {
        if (err) throw err;
        res.render('employees', { employees: results });
    });
});

app.get('/employees/add', isAuthenticated, (req, res) => {
    res.render('add-employee');
});

app.post('/employees/add', isAuthenticated, (req, res) => {
    const { name, position, salary } = req.body;
    db.query('INSERT INTO employees (name, position, salary) VALUES (?, ?, ?)', [name, position, salary], (err) => {
        if (err) throw err;
        res.redirect('/employees');
    });
});

app.get('/employees/edit/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM employees WHERE id = ?', [id], (err, results) => {
        if (err) throw err;
        res.render('edit-employee', { employee: results[0] });
    });
});

app.post('/employees/edit/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const { name, position, salary } = req.body;
    db.query('UPDATE employees SET name = ?, position = ?, salary = ? WHERE id = ?', [name, position, salary, id], (err) => {
        if (err) throw err;
        res.redirect('/employees');
    });
});

app.post('/employees/delete/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM employees WHERE id = ?', [id], (err) => {
        if (err) throw err;
        res.redirect('/employees');
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
