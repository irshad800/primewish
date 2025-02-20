const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const authDB = require('../models/auth_schema'); // Ensure correct path
const authRouter = express.Router();

// Initialize Passport
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost:8080/api/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const { email, name, picture } = profile._json;
        let user = await authDB.findOne({ email });

        if (!user) {
            user = new authDB({
                username: email,
                name,
                email,
                verified: true,
                profilePicture: picture || ''
            });
            await user.save();
        }
        return done(null, user);
    } catch (err) {
        done(err, null);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => done(null, await authDB.findById(id)));

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_ID,
        pass: process.env.EMAIL_APP_PASSWORD
    }
});

// Generate a verification token
const generateVerificationToken = () => Math.random().toString(36).substring(2);

// Function to send verification email
const sendVerificationEmail = async (email, token) => {
  const verificationUrl = `http://localhost:8080/api/auth/verify-email/${token}`;
  console.log("🔗 Email verification link:", verificationUrl); // Debugging

  const mailOptions = {
      from: process.env.EMAIL_ID,
      to: email,
      subject: 'Email Verification',
      text: `Click here to verify your email: ${verificationUrl}`
  };

  await transporter.sendMail(mailOptions);
};

// 📌 **User Registration Route**
authRouter.post('/register', async (req, res) => {
  try {
      const { username, password, name, email, phone } = req.body;

      if (await authDB.findOne({ $or: [{ username }, { phone }, { email }] })) {
          return res.status(400).json({ Success: false, Message: 'User already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const verificationToken = generateVerificationToken();

      // Save user in database
      const newUser = new authDB({
          username,
          password: hashedPassword,
          name,
          email,
          phone,
          verificationToken,  // ✅ Ensure this is saved
          verified: false
      });

      await newUser.save();

      // 🔍 Check if token is actually saved
      const checkUser = await authDB.findOne({ email });
      console.log("🔍 User after saving:", checkUser);

      if (!checkUser.verificationToken) {
          return res.status(500).json({ Success: false, Message: "Token was not saved properly" });
      }

      console.log("✅ User registered with token:", verificationToken);

      await sendVerificationEmail(email, verificationToken);

      res.json({ Success: true, Message: 'Registration successful. Check email for verification.' });
  } catch (error) {
      console.error("❌ Registration Error:", error);
      res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
  }
});



// 📌 **Google Authentication Routes**
authRouter.get('/auth/google', passport.authenticate('google', { scope: ['email', 'profile'] }));

authRouter.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect(`http://127.0.0.1:5500/bemet/Authea_v1.0/HTML/dist/auth-login.html?email=${req.user.email}`);
    }
);

// 📌 **Email Verification Route**
authRouter.get('/verify-email/:token', async (req, res) => {
  try {
      const token = req.params.token;
      console.log("🔍 Received verification token:", token);

      // Find user with the token
      const user = await authDB.findOne({ verificationToken: token });

      if (!user) {
          console.log("❌ Token not found in the database.");
          return res.status(400).json({ Success: false, Message: 'Invalid or expired token' });
      }

      console.log("✅ User found:", user);

      user.verified = true;
      user.verificationToken = ''; // Clear token after verification
      await user.save();
      console.log("✅ Email verified successfully!");

      res.redirect('http://127.0.0.1:5500/verified-success.html');
  } catch (error) {
      console.error("❌ Verification Error:", error);
      res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
  }
});



// 📌 **Login Route**
authRouter.post('/login', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        // Check if user exists (by username or email)
        const user = await authDB.findOne({ $or: [{ username }, { email }] });

        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ Success: false, Message: 'Invalid credentials' });
        }

        if (!user.verified) {
            return res.status(400).json({ Success: false, Message: 'Email not verified' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ Success: true, Message: 'Login successful', token });
    } catch (error) {
        console.error("❌ Login Error:", error);
        res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
    }
});

module.exports = authRouter;
