const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const authDB = require('../models/auth_schema'); // User schema
// const deletedDB = require('../models/deleted_users_schema'); // Deleted users schema
const authRouter = express.Router();

// const applicationDB = require("../models/application_schema"); 
const { ensureAuth } = require('../middleware/authMiddleware');
// const redisClient = require('redis').createClient();

const googleClient = new OAuth2Client(process.env.CLIENT_ID);
const activeTokens = new Set(); // Store active tokens until logout
// 📌 Nodemailer setup


const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true', // Convert string to boolean
    auth: {
        user: process.env.EMAIL_ID,
        pass: process.env.EMAIL_APP_PASSWORD
    }
});

// 📌 Generate random verification token
const generateVerificationToken = () => Math.random().toString(36).substring(2);
const generateVerificationCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// 📌 Send email verification link
// 📌 Send email verification link
const sendVerificationEmail = async (email, token) => {
    const verificationUrl = `http://localhost:8081/api/auth/verify-email/${token}`;

    const mailOptions = {
        from: process.env.EMAIL_ID,
        to: email,
        subject: "Email Verification",
        html: `
        <div style="max-width: 600px; margin: auto; padding: 25px; border-radius: 12px;
            box-shadow: 0px 4px 10px rgba(0,0,0,0.15); background: #f9f9f9; font-family: Arial, sans-serif; text-align: center;">

            <!-- Header -->
            <h1 style="color: #0056b3; font-size: 24px; margin-bottom: 10px;">Welcome to <span style="color: #ff6600;">PRIME WISH</span>!</h1>
            <p style="font-size: 16px; color: #333;">You're just one step away from unlocking exclusive benefits. Please verify your email to activate your account.</p>

            <!-- Verification Box -->
            <div style="padding: 20px; border: 2px solid #ff6600; border-radius: 10px; background: #ffffff; margin: 20px auto;">
                <p style="font-size: 18px; color: #444;">Click the button below to verify your email and start your journey with <b>WISH I CLUB</b>.</p>

                <!-- Call-to-Action Button -->
                <a href="${verificationUrl}" style="display: inline-block; padding: 14px 24px; font-size: 18px; color: #ffffff; background: #ff6600; text-decoration: none; border-radius: 8px; font-weight: bold; margin-top: 10px;">
                    ✅ Verify My Email
                </a>

                <p style="margin-top: 15px; font-size: 14px; color: #777;">If you didn’t request this, please ignore this email.</p>
            </div>

            <!-- Footer -->
            <p style="text-align: center; font-size: 12px; color: #888; margin-top: 15px;">
                Need help? Contact our support team at <a href="mailto:support@wishi.club" style="color: #ff6600; text-decoration: none;">info@wishiclub.com</a>.
            </p>
        </div>
        `
    };

    await transporter.sendMail(mailOptions);
};


// ✅ **Check if username, email, or phone exists**
authRouter.post('/check-availability', async (req, res) => {
    try {
        const { type, value } = req.body;
        const exists = await authDB.findOne({ [type]: value }) ? true : false;
        res.json({ exists });
    } catch (error) {
        console.error(`Error checking ${type}:`, error);
        res.status(500).json({ Success: false, Message: 'Internal Server Error' });
    }
});

// ✅ **Email Verification Route**
authRouter.get('/verify-email/:token', async (req, res) => {
    try {
        const { token } = req.params; // ✅ Correct usage of params

        // Find user by verification token
        const user = await authDB.findOne({ verificationToken: token });

        if (!user) {
            console.log('Email verification failed: Invalid or expired token');
            return res.status(400).json({
                Success: false,
                Message: 'Invalid or expired token',
            });
        }

        // Update user as verified
        user.verified = true;
        user.verificationToken = ''; // Clear the token after use
        await user.save();

        // ✅ Generate a new JWT token for the user
        const authToken = jwt.sign(
            { userId: user.userId, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        console.log('✅ Email verified successfully for user:', user.username);

        // Redirect user to front-end with new authToken
        return res.redirect(`https://www.wishiclub.com/verify-email.html?token=${authToken}`);
    } catch (error) {
        console.error('❌ Error in verify-email route:', error.message);
        return res.status(500).json({
            Success: false,
            Message: 'Internal Server Error',
            ErrorMessage: error.message,
        });
    }
});


// ✅ **User Registration**
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
        console.error(`❌ Registration error: ${error.message}`);
        res.status(500).json({ Success: false, Message: 'Internal Server Error' });
    }
});

authRouter.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await authDB.findOne({ $or: [{ username }, { email: username }] });

        // Always return the same error message for security
        const invalidMessage = 'Incorrect username or password';

        if (!user) return res.status(400).json({ Success: false, Message: invalidMessage });
        if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ Success: false, Message: invalidMessage });
        if (!user.verified) return res.status(400).json({ Success: false, Message: 'Email not verified' });

        const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ Success: true, Message: 'Login successful', token });
    } catch (error) {
        console.error(`❌ Login Error: ${error.message}`);
        res.status(500).json({ Success: false, Message: 'Internal Server Error' });
    }
});

// ✅ **Google Authentication**
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
            user = new authDB({ username: email, name, email, verified: true, profilePicture: picture || '' });
            await user.save();
        }

        const jwtToken = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ Success: true, Message: 'Google Login Successful', token: jwtToken });
    } catch (error) {
        console.error(`❌ Google Login Error: ${error.message}`);
        res.status(401).json({ Success: false, Message: 'Invalid Google Token' });
    }
});

// ✅ **Forgot Password**
authRouter.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await authDB.findOne({ email });

        if (!user) return res.status(400).json({ Success: false, Message: 'User not found' });

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
        console.error(`❌ Forgot Password Error: ${error.message}`);
        res.status(500).json({ Success: false, Message: 'Internal Server Error' });
    }
});

// ✅ **Reset Password**
authRouter.post('/reset-password', async (req, res) => {
    try {
        const { email, verificationCode, newPassword } = req.body;
        const user = await authDB.findOne({ email, verificationToken: verificationCode });

        if (!user) return res.status(400).json({ Success: false, Message: 'Invalid or expired verification code' });

        user.password = await bcrypt.hash(newPassword, 12);
        user.verificationToken = '';
        await user.save();

        res.json({ Success: true, Message: 'Password reset successful' });
    } catch (error) {
        console.error(`❌ Reset Password Error: ${error.message}`);
        res.status(500).json({ Success: false, Message: 'Internal Server Error' });
    }
});

module.exports = authRouter;
