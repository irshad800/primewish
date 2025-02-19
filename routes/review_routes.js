// routes/review_routes.js
const express = require('express');
const jwt = require('jsonwebtoken');
const authDB = require('../models/auth_schema'); // Import auth schema
const Review = require('../models/review_schema'); // Import review schema
const reviewRouter = express.Router();

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    console.error('Access denied. No token provided.');
    return res.status(401).json({ Success: false, Message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId; // Attach userId to the request object
    next();
  } catch (error) {
    console.error('Invalid token:', error);  // Log the specific error
    res.status(400).json({ Success: false, Message: 'Invalid token.' });
  }
};

// Submit a review
reviewRouter.post('/submit', verifyToken, async (req, res) => {
  try {
    const { message } = req.body;

    // Fetch user details from authDB
    const user = await authDB.findById(req.userId);
    if (!user) {
      console.error('User not found with ID:', req.userId);  // Log if user is not found
      return res.status(404).json({ Success: false, Message: 'User not found.' });
    }

    // Create a new review
    const review = new Review({
      userId: req.userId,
      name: user.name,
      message,
    });

    await review.save();

    res.status(201).json({
      Success: true,
      Message: 'Review submitted successfully.',
      Review: review,
    });
  } catch (error) {
    console.error('Error submitting review:', error);  // Log error if review submission fails
    res.status(500).json({ Success: false, Message: 'Internal Server Error' });
  }
});

// Get all reviews
reviewRouter.get('/all', async (req, res) => {
  try {
    const reviews = await Review.find()
      .populate('userId', 'name email') // Populate user details (name and email)
      .exec();
      
    res.status(200).json({
      Success: true,
      Message: 'Reviews fetched successfully.',
      Reviews: reviews,
    });
  } catch (error) {
    console.error('Error fetching reviews:', error);  // Log error if fetching reviews fails
    res.status(500).json({ Success: false, Message: 'Internal Server Error' });
  }
});

module.exports = reviewRouter;
