const express = require('express');
const path = require('path');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const fs = require('fs');

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'Login and Signup')));

// MySQL database setup
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Chiku@4009',
    database: 'login-signup',
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err.message);
    } else {
        console.log('Connected to MySQL database');
        // Create a 'credentials' table if it doesn't exist
        db.query(`
            CREATE TABLE IF NOT EXISTS credentials (
                phone BIGINT UNIQUE PRIMARY KEY,
                password VARCHAR(255)
            )
        `, (err) => {
            if (err) {
                console.error('Error creating table:', err.message);
            }
        });
    }
});

// Function to append user data to JSON file
function appendUserDataToFile(userData) {
    let existingData = [];
    try {
        if (fs.existsSync('userdata.json')) {
            existingData = JSON.parse(fs.readFileSync('userdata.json'));
        }
    } catch (error) {
        console.error('Error reading JSON file:', error.message);
    }

    existingData.push(userData);
    fs.writeFileSync('userdata.json', JSON.stringify(existingData, null, 2));
}

// Check if JSON file exists, if not create it
if (!fs.existsSync('userdata.json')) {
    fs.writeFileSync('userdata.json', '[]');
}

// Authentication endpoint for login
app.post('/auth/login', async (req, res) => {
    const {phone, password } = req.body;

    // Retrieve hashed password from the database based on the phone number
    const query = 'SELECT * FROM credentials WHERE phone = ?';
    db.query(query, [phone], async (err, results) => {
        if (err) {
            console.error('Error retrieving user:', err.message);
            return res.status(500).json({ success: false, message: 'Internal Server Error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const hashedPassword = results[0].password;

        // Compare hashed password with the submitted password
        const passwordMatch = await bcrypt.compare(password, hashedPassword);

        if (passwordMatch) {
            res.json({ success: true });

        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    });
});

// Authentication endpoint for user registration
app.post('/auth/register', async (req, res) => {   
    const { phone, password } = req.body;

    // Hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the 'credentials' table
    const insertQuery = 'INSERT INTO credentials (phone, password) VALUES (?, ?)';
    db.query(insertQuery, [phone, hashedPassword], (err) => {
        if (err) {
            console.error('Error inserting user:', err.message);
            return res.status(400).json({ success: false, message: 'Phone number already exists' });
        }

        // Append phone number and hashed password to JSON file
        const userData = { phone, password: hashedPassword };
        appendUserDataToFile(userData);

        res.json({ success: true });
    });
});

app.get('/api/login-info', (req, res) => {
    // Read the JSON file containing login information
    try {
        const loginData = JSON.parse(fs.readFileSync('userdata.json'));
        res.json(loginData);
    } catch (error) {
        console.error('Error reading JSON file:', error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
    //res.sendFile(path.join(__dirname, 'Login and Signup', 'index.html'));
});

app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});