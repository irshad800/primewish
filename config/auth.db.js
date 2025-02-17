// // config/auth.db.js
// const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs');
// require('dotenv').config();  // Load environment variables

// // MongoDB Connection
// const connectDB = async () => {
//   try {
//     await mongoose.connect(process.env.MONGODB_URI, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true,
//     });
//     console.log('Database Connected');
//   } catch (err) {
//     console.error('Database connection error:', err.message);
//     process.exit(1); // Exit the process with failure
//   }
// };

// // Import the User model
// // config/auth.db.js
// const User = require('../models/user');  // Lowercase 'u'


// // Export the DB connection and User model
// module.exports = { connectDB, User };
