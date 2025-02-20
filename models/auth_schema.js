const mongoose = require('mongoose');

const authSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: false },  // Optional for Google Sign-In
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: Number, required: false },
    verified: { type: Boolean, default: false },  // Default false until email is verified
    verificationToken: { type: String, required: false },  // ✅ Add this field
});

const authDB = mongoose.model('auth', authSchema);

module.exports = authDB;
