const mongoose = require('mongoose');

const authSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: false,  // Optional for Google Sign-In
    },
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    phone: {
        type: Number,
        required: false,  // Optional, depending on your use case
    },
    verified: {
        type: Boolean,
        default: true,  // Assuming the email from Google is verified
    }
});

// Correct export of the model
const authDB = mongoose.model('auth', authSchema);

module.exports = authDB;  // export once