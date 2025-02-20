const jwt = require('jsonwebtoken');

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];  // Get token from 'Authorization' header
  if (!token) {
    return res.status(401).json({ Success: false, Message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId; // Attach userId to the request object
    next();
  } catch (error) {
    console.error('Invalid token:', error); // Log the specific error
    return res.status(400).json({ Success: false, Message: 'Invalid token.' });
  }
};

module.exports = { verifyToken };
