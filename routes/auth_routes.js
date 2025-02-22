const express = require('express');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const authDB = require('../models/auth_schema');
const authRouter = express.Router();

const googleClient = new OAuth2Client(process.env.CLIENT_ID);

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_ID,
        pass: process.env.EMAIL_APP_PASSWORD
    }
});

const generateVerificationToken = () => Math.random().toString(36).substring(2);
const generateVerificationCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// Function to send verification email
const sendVerificationEmail = async (email, token) => {
     const verificationUrl = `https://primewish-ae.onrender.com/api/auth/verify-email/${token}`;
    const mailOptions = {
        from: process.env.EMAIL_ID,
        to: email,
        subject: 'Email Verification',
        text: `Click here to verify your email: ${verificationUrl}`
    };
    await transporter.sendMail(mailOptions);
};



authRouter.get('/verify-email/:token', async (req, res) => {
    try {
      const { token } = req.params;
      // Find the user with the matching verification token
      const user = await authDB.findOne({ verificationToken: token });
      if (!user) {
        return res.status(400).send("Invalid or expired verification link.");
      }
      // Update the user record to mark as verified and clear the token
      user.verified = true;
      user.verificationToken = "";
      await user.save();
  
      // Redirect the user to your frontend page
      res.redirect("http://127.0.0.1:5501/main_files/index.html");
    } catch (error) {
      console.error("Email verification error:", error);
      res.status(500).send("Internal Server Error");
    }
  });
  

// 📌 **User Registration Route**
authRouter.post('/register', async (req, res) => {
    try {
        const { username, password, name, email, phone } = req.body;

        if (await authDB.findOne({ $or: [{ username }, { phone }, { email }] })) {
            return res.status(400).json({ Success: false, Message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const verificationToken = generateVerificationToken();

        const newUser = new authDB({
            username,
            password: hashedPassword,
            name,
            email,
            phone,
            verificationToken,
            verified: false
        });

        await newUser.save();
        await sendVerificationEmail(email, verificationToken);
        res.json({ Success: true, Message: 'Registration successful. Check email for verification.' });
    } catch (error) {
        res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
    }
});

// 📌 **Login Route (Normal Login)**
authRouter.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await authDB.findOne({ $or: [{ username }, { email: username }] });

        if (!user) {
            console.log(`❌ Login failed: User '${username}' not found.`);
            return res.status(400).json({ Success: false, Message: 'Invalid credentials' });
        }

        if (!await bcrypt.compare(password, user.password)) {
            console.log(`❌ Login failed: Incorrect password for '${username}'.`);
            return res.status(400).json({ Success: false, Message: 'Invalid credentials' });
        }

        if (!user.verified) {
            console.log(`⚠️ Login failed: Email not verified for '${username}'.`);
            return res.status(400).json({ Success: false, Message: 'Email not verified' });
        }

        const token = jwt.sign(
            { userId: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        console.log(`✅ Login successful for '${username}'. Token generated.`);
        res.json({ Success: true, Message: 'Login successful', token });
    } catch (error) {
        console.error(`❌ Login Error: ${error.message}`);
        res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
    }
});
// 📌 **Google Authentication Route**
authRouter.post('/google-login', async (req, res) => {
    try {
        const { token } = req.body;
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.CLIENT_ID
        });

        const { email, name, picture } = ticket.getPayload();
        let user = await authDB.findOne({ email });

        if (!user) {
            console.log(`🔵 New Google user detected: '${email}'. Creating new account.`);
            user = new authDB({
                username: email,
                name,
                email,
                verified: true,
                profilePicture: picture || ''
            });
            await user.save();
        } else {
            console.log(`✅ Google Login successful for '${email}'.`);
        }

        const jwtToken = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        console.log(`🔑 Google Login: JWT Token generated for '${email}'.`);
        res.json({ Success: true, Message: 'Google Login Successful', email: user.email, token: jwtToken });
    } catch (error) {
        console.error(`❌ Google Login Error: ${error.message}`);
        res.status(401).json({ Success: false, Message: 'Invalid Google Token' });
    }
});
// 📌 **Forgot Password Route**
authRouter.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await authDB.findOne({ email });

        if (!user) {
            return res.status(400).json({ Success: false, Message: 'User not found' });
        }

        const verificationCode = generateVerificationCode();
        user.verificationToken = verificationCode;
        await user.save();

        const mailOptions = {   
            from: process.env.EMAIL_ID,
            to: email,
            subject: 'Password Reset Code',
            text: `Your password reset verification code is: ${verificationCode}`
        };

        await transporter.sendMail(mailOptions);
        res.json({ Success: true, Message: 'Verification code sent to email' });
    } catch (error) {
        res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
    }
});

// 📌 **Reset Password Route**
authRouter.post('/reset-password', async (req, res) => {
    try {
        const { email, verificationCode, newPassword } = req.body;
        const user = await authDB.findOne({ email, verificationToken: verificationCode });

        if (!user) {
            return res.status(400).json({ Success: false, Message: 'Invalid or expired verification code' });
        }

        user.password = await bcrypt.hash(newPassword, 12);
        user.verificationToken = '';
        await user.save();

        res.json({ Success: true, Message: 'Password reset successful' });
    } catch (error) {
        res.status(500).json({ Success: false, Message: 'Internal Server Error', ErrorMessage: error.message });
    }
});

module.exports = authRouter;
