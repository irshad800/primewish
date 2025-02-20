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
        user = new authDB({ username: email, name, email, verified: true, profilePicture: picture || '' });
        await user.save();
      }
      return done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => done(null, await authDB.findById(id)));

  // Nodemailer transporter
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_ID, pass: process.env.EMAIL_APP_PASSWORD },
  });

  const generateVerificationToken = () => Math.random().toString(36).substring(2);

  const sendVerificationEmail = async (email, token) => {
    const verificationUrl = `${process.env.FRONTEND_URL}/verified-success.html?token=${token}`;
    const mailOptions = { from: process.env.EMAIL_ID, to: email, subject: 'Email Verification', text: `Verify your email: ${verificationUrl}` };
    await transporter.sendMail(mailOptions);
  };

  // Register Route
  authRouter.post('/register', async (req, res) => {
    try {
      const { username, password, name, email, phone } = req.body;
      if (await authDB.findOne({ $or: [{ username }, { phone }, { email }] })) {
        return res.status(400).json({ Success: false, Message: 'User already exists' });
      }
      const hashedPassword = await bcrypt.hash(password, 12);
      const verificationToken = generateVerificationToken();
      const result = await new authDB({ username, password: hashedPassword, name, email, phone, verificationToken, verified: false }).save();
      await sendVerificationEmail(email, verificationToken);
      res.json({ Success: true, Message: 'Registration successful. Check email for verification.' });
    } catch (error) {
      res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
    }
  });

  // Google Auth
  authRouter.get('/auth/google', passport.authenticate('google', { scope: ['email', 'profile'] }));
  authRouter.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    res.redirect(`http://127.0.0.1:5500/bemet/Authea_v1.0/HTML/dist/auth-login.html?email=${req.user.email}`);
  });

  // Email Verification
  authRouter.get('/verify-email/:token', async (req, res) => {
    try {
      const user = await authDB.findOne({ verificationToken: req.params.token });
      if (!user) return res.status(400).json({ Success: false, Message: 'Invalid or expired token' });
      user.verified = true;
      user.verificationToken = '';
      await user.save();
      res.redirect(`${process.env.FRONTEND_URL}/verified-success.html`);
    } catch (error) {
      res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
    }
  });

  // Login Route

  authRouter.post('/login', async (req, res) => {
    try {
      const { username, password, email } = req.body;

      // Check if either username or email is provided
      const user = await authDB.findOne({ 
        $or: [{ username }, { email }] 
      });

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
      res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
    }
  });

  module.exports = authRouter;
