// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { MongoClient } = require('mongodb');
const crypto = require('crypto');
const dotenv = require('dotenv');

// Create an Express application
const app = express();
const port = process.env.PORT || 3000;

// Generate a random secret key for session management
const secretKey = crypto.randomBytes(64).toString('hex');

// Load environment variables from a .env file
dotenv.config();

// MongoDB connection string
const dbConnectionString = 'mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+1.10.6';

// Connect to MongoDB
async function connectToMongoDB() {
    const client = new MongoClient(dbConnectionString, { useUnifiedTopology: true });

    try {
        await client.connect();
        console.log('Connected to MongoDB');

        // Get a reference to the Users collection
        const db = client.db('Authentication');
        const User = db.collection('Users');

        // Middleware for parsing request bodies and managing sessions
        app.use(bodyParser.urlencoded({ extended: true }));
        app.use(session({ secret: secretKey, resave: false, saveUninitialized: false }));

        // Define routes

        // Home page route
        app.get('/', (req, res) => {
            res.sendFile(__dirname + '/html/index.html');
        });

        // User registration route
        app.post('/register', async (req, res) => {
            const { email, password } = req.body;
            try {
                // Check if the email is already registered
                const existingUser = await User.findOne({ email });
                if (existingUser) {
                    res.sendFile(__dirname + '/html/error.html');
                } else {
                    // Hash the user's password before storing it
                    const hashedPassword = await bcrypt.hash(password, 10);
                    const user = { email, password: hashedPassword };
                    await User.insertOne(user);
                    req.session.user = user;
                    res.redirect('/dashboard');
                }
            } catch (error) {
                console.error(error);
                res.redirect('/');
            }
        });

        app.get('/error', (req, res) => {
            res.sendFile(__dirname + '/html/error.html');
        });


        // User login route
        app.post('/login', async (req, res) => {
            const { email, password } = req.body;
            try {
                const user = await User.findOne({ email });

                if (user && (await bcrypt.compare(password, user.password))) {
                    // Store user information in the session upon successful login
                    req.session.user = user;
                    res.redirect('/dashboard');
                } else {
                    res.redirect('/html/login.html');
                }
            } catch (error) {
                console.error(error);
                res.redirect('/html/login.html');
            }
        });

        // Dashboard route
        app.get('/dashboard', (req, res) => {
            if (req.session.user) {
                res.sendFile(__dirname + '/html/dashboard.html');
            } else {
                res.redirect('/html/login.html');
            }
        });

        // Login page route
        app.get('/login', (req, res) => {
            res.sendFile(__dirname + '/html/login.html');
        });

        // Start the server
        app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
    }
}

// Call the function to connect to MongoDB and start the server
connectToMongoDB();
