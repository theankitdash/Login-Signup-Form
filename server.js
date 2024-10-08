const express = require('express');
const path = require('path');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const port = process.env.PORT || 3000;

// Initialize express-session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your_secret_key',
    resave: false,
    saveUninitialized: true
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MySQL database setup
const db = mysql.createConnection({
    host: process.env.AZURE_MYSQL_HOST || 'localhost',
    user: process.env.AZURE_MYSQL_USER || 'root',
    password: process.env.AZURE_MYSQL_PASSWORD || 'Chiku@4009',
    database: process.env.AZURE_MYSQL_DATABASE || 'login-signup',
    port: process.env.AZURE_MYSQL_PORT || 3306,
    ssl: process.env.AZURE_MYSQL_SSL ? JSON.parse(process.env.AZURE_MYSQL_SSL) : false
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

// Create a 'personal_details' table if it doesn't exist
db.query(`
    CREATE TABLE IF NOT EXISTS personal_details (
        phone BIGINT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        gender VARCHAR(10) NOT NULL,
        date_of_birth DATE NOT NULL,
        FOREIGN KEY (phone) REFERENCES credentials(phone) ON DELETE CASCADE ON UPDATE CASCADE
    )
`, (err) => {
    if (err) {
        console.error('Error creating table:', err.message);
    }
});

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
            // Store the phone number in the session
            req.session.phone = phone;
            req.session.password = hashedPassword;
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

        req.session.phone = phone;
        req.session.password = hashedPassword;
        res.json({ success: true });
    });
});

// Endpoint to verify phone number and date of birth
app.post('/auth/verify', async (req, res) => {
    const { phone, dob } = req.body;

    try {
        // Verify Date of Birth
        const query = 'SELECT * FROM personal_details WHERE phone = ? AND date_of_birth = ?';
        db.query(query, [phone, dob], (err, results) => {
            if (err) {
                console.error('Error retrieving details:', err.message);
                return res.status(500).json({ success: false, message: 'Internal Server Error' });
            }

            if (results.length === 0) {
                return res.status(400).json({ success: false, message: 'Verification failed' });
            }

            res.json({ success: true });
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Endpoint to reset password
app.post('/auth/resetPassword', async (req, res) => {
    const { phone, newPassword } = req.body;

    try {
        const newHashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the hashed password in the database
        const updateQuery = 'UPDATE credentials SET password = ? WHERE phone = ?';
        db.query(updateQuery, [newHashedPassword, phone], (err) => {
            if (err) {
                console.error('Error updating password:', err.message);
                return res.status(500).json({ success: false, message: 'Internal Server Error' });
            }
            res.json({ success: true, message: 'Password updated successfully' });
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

//Endpoint to get current phone number and password
app.get('/Details', (req, res) => {
    // Check if the user is logged in
    if (!req.session.phone || !req.session.password) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    // Fetch current credentials for the logged-in user
    const phone = req.session.phone;
    const password = req.session.password;

    // single query using JOIN
    const Query = `
        SELECT name, gender, date_of_birth
        FROM personal_details 
        WHERE phone = ?
    `;

    // Execute the combined query
    db.query(Query, [phone], (err, results) => {
        if (err) {
            console.error('Error retrieving details:', err.message);
            return res.status(500).json({ success: false, message: 'Internal Server Error' });
        }

        if (results.length === 0) {
            return res.json({ success: true, message: 'No details available' });
        }


        // Send the response with combined personal and budget information
        const { name, gender, date_of_birth: dateOfBirth} = results[0];
        res.json({ success: true, phone, password, name, gender, dateOfBirth});
    });
});

// Endpoint to save personal details
app.post('/savePersonalDetails', (req, res) => {
    // Check if the user is logged in
    if (!req.session.phone || !req.session.password) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const { name, gender, dateOfBirth } = req.body;
    const phone = req.session.phone;

    // Insert or update personal details for the user
    const insertOrUpdateQuery = `
        INSERT INTO personal_details (phone, name, gender, date_of_birth)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE name=?, gender=?, date_of_birth=?
    `;
    db.query(insertOrUpdateQuery, [phone, name, gender, dateOfBirth, name, gender, dateOfBirth], (err) => {
        if (err) {
            console.error('Error saving personal details:', err.message);
            return res.status(500).json({ success: false, message: 'Internal Server Error' });
        }
        res.json({ success: true, message: 'Personal details saved successfully' });
    });
});

//Endpoint to change the user's password
app.post('/changePassword', async (req, res) => {
    // Check if the user is logged in
    if (!req.session.phone || !req.session.password) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const { newPassword } = req.body;

    try {
        // Hash the new password
        const newHashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the hashed password in the session
        req.session.password = newHashedPassword;

        // Update the hashed password in the database
        const phone = req.session.phone;
        const updateQuery = 'UPDATE credentials SET password = ? WHERE phone = ?';
        db.query(updateQuery, [newHashedPassword, phone], (err) => {
            if (err) {
                console.error('Error updating password:', err.message);
                return res.status(500).json({ success: false, message: 'Internal Server Error' });
            }
            res.json({ success: true, message: 'Password updated successfully' });
        });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

//Endpoint for user logout
app.get('/logout', (req, res) => {
    // Clear session data
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ success: false, message: 'Internal Server Error' });
        }
        // Redirect user to the login page
        res.redirect('http://localhost:3000'); // Change the path to your actual login page
    });
});


app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
});