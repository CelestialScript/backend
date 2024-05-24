const express = require('express');
const firebase = require('firebase');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

// Initialize Firebase (Client SDK)
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID
};

firebase.initializeApp(firebaseConfig);

const app = express();
app.use(bodyParser.json());

// Sign-up route
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userRecord = await firebase.auth().createUserWithEmailAndPassword(email, password);
    res.status(201).send({ uid: userRecord.user.uid, email: userRecord.user.email });
  } catch (error) {
    res.status(400).send(`Error creating user: ${error.message}`);
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userRecord = await firebase.auth().signInWithEmailAndPassword(email, password);
    const idToken = await userRecord.user.getIdToken();
    res.status(200).send({ token: idToken });
  } catch (error) {
    res.status(400).send(`Error logging in: ${error.message}`);
  }
});

// Middleware to verify Firebase ID Token
const authenticate = async (req, res, next) => {
  const idToken = req.headers.authorization?.split('Bearer ')[1];

  if (!idToken) {
    return res.status(403).send('Unauthorized');
  }

  try {
    const decodedToken = await firebase.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    res.status(403).send('Unauthorized');
  }
};

// Protected route example
app.get('/profile', authenticate, async (req, res) => {
  const userId = req.user.uid;

  try {
    const userRecord = await firebase.auth().getUser(userId);
    res.status(200).send(userRecord);
  } catch (error) {
    res.status(500).send(`Error fetching user data: ${error.message}`);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
