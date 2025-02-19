const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const authDB = require('../models/auth_schema'); // Ensure correct path
const authRouter = express.Router();
const cors = require('cors');
const path = require('path');

// Initialize Passport
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: 'http://localhost:8080/api/auth/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const { email, name, picture } = profile._json;

    console.log('Google sign-in successful. User email:', email);

    // Check if user already exists
    let user = await authDB.findOne({ email });
    if (!user) {
      // If the user does not exist, register the user
      user = new authDB({
        username: email,
        password: '',  // No password for Google users
        name,
        email,
        phone: '',  // Optional for Google users
        verified: true,  // Assuming the Google sign-in email is always verified
        profilePicture: picture || '',  // Save the Google profile picture
      });
      await user.save();  // Save the user to DB
    }

    // Pass user info to the next middleware
    return done(null, user);
  } catch (err) {
    console.error('Error in Google Strategy:', err);
    done(err, null);
  }
}));

// Serialize and deserialize user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await authDB.findById(id);
  done(null, user);
});

// Create a Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_ID,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
});

// Generate a random verification token
function generateVerificationToken() {
  return Math.random().toString(36).substring(2); // Generates a random string token
}

// Send verification email
async function sendVerificationEmail(email, token) {
  const verificationUrl = `${process.env.FRONTEND_URL}/verified-success.html?token=${token}`;

  const mailOptions = {
    from: process.env.EMAIL_ID,
    to: email,
    subject: 'Email Verification',
    text: `Please verify your email by clicking on the following link: ${verificationUrl}`,
  };

  await transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.log('Error sending verification email:', err);
    } else {
      console.log('Verification email sent:', info.response);
    }
  });
}

// Register Route (for manual registration)
authRouter.post('/register', async (req, res) => {
  try {
    const { username, password, name, email, phone } = req.body;

    // Check if the username, phone, or email already exists
    const oldUser = await authDB.findOne({ username });
    if (oldUser) {
      return res.status(400).json({
        Success: false,
        Message: 'Username already exists. Please Log In',
      });
    }

    const oldPhone = await authDB.findOne({ phone });
    if (oldPhone) {
      return res.status(400).json({
        Success: false,
        Message: 'Phone number already exists',
      });
    }

    const oldEmail = await authDB.findOne({ email });
    if (oldEmail) {
      return res.status(400).json({
        Success: false,
        Message: 'Email already exists',
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate a verification token
    const verificationToken = generateVerificationToken();

    // Save user data to DB
    let reg = {
      username,
      password: hashedPassword,
      name,
      email,
      phone,
      verificationToken,
      verified: false,
    };

    const result = await authDB(reg).save();

    if (result) {
      // Send verification email
      await sendVerificationEmail(email, verificationToken);

      return res.json({
        Success: true,
        Message: 'Registration Successful. Please check your email for verification link.',
      });
    } else {
      return res.json({
        Success: false,
        Message: 'Registration Failed. Please try again later.',
      });
    }
  } catch (error) {
    console.error('Error in register route:', error.message);
    return res.status(500).json({
      Success: false,
      Message: 'Internal Server Error',
      ErrorMessage: error.message,
    });
  }
});

// Google Login Route
authRouter.get('/auth/google', passport.authenticate('google', { scope: ['email', 'profile'] }));

// Google Callback Route
authRouter.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', { failureRedirect: '/login' }, (err, user, info) => {
    if (err) {
      console.error('Error during Google authentication:', err);
      return res.status(500).json({
        Success: false,
        Message: 'Internal Server Error',
        ErrorMessage: err.message,
      });
    }
    if (!user) {
      console.error('Google authentication failed: No user returned');
      return res.redirect('/login');
    }

    console.log('Google sign-in successful. User details:', user);

    // Redirect to your frontend with the user's email in the query string
    res.redirect(`http://127.0.0.1:5500/bemet/Authea_v1.0/HTML/dist/auth-login.html?email=${user.email}`);
  })(req, res, next);
});

// Email Verification Route
authRouter.get('/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;

    // Find the user by the verification token
    const user = await authDB.findOne({ verificationToken: token });

    if (!user) {
      console.log('Email verification failed: Invalid or expired token');
      return res.status(400).json({
        Success: false,
        Message: 'Invalid or expired token',
      });
    }

    // Update the user's verified status
    user.verified = true;
    user.verificationToken = '';  // Clear the token once verified

    // Save the updated user
    await user.save();

    console.log('Email verified successfully for user:', user.username);
    // Redirect to the frontend success page
    res.redirect(`${process.env.FRONTEND_URL}/verified-success.html`);
  } catch (error) {
    console.error('Error in verify-email route:', error.message);
    return res.status(500).json({
      Success: false,
      Message: 'Internal Server Error',
      ErrorMessage: error.message,
    });
  }
});

// Login Route
authRouter.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if the user exists
    const user = await authDB.findOne({ username });
    if (!user) {
      console.log('Login failed: User not found');
      return res.status(400).json({
        Success: false,
        Message: 'User not found. Please check your username.',
      });
    }

    // Check if the user's email is verified
    if (!user.verified) {
      console.log('Login failed: Email not verified');
      return res.status(400).json({
        Success: false,
        Message: 'Email not verified. Please check your inbox.',
      });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Login failed: Invalid password');
      return res.status(400).json({
        Success: false,
        Message: 'Invalid password. Please try again.',
      });
    }

    // Generate a JWT token for the user
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || '4d3b7914f53cd6e3b9f1b8e5c46b8d3b1e9f0dba989b24a33b29288c0c4c8b93',
      { expiresIn: '1h' }
    );

    console.log('Login successful for user:', username);
    res.json({
      Success: true,
      Message: 'Login successful',
      token,
    });
  } catch (error) {
    console.error('Error in login route:', error.message);
    return res.status(500).json({
      Success: false,
      Message: 'Internal Server Error',
      ErrorMessage: error.message,
    });
  }
});

module.exports = authRouter;