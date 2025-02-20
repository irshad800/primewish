const express = require('express');
const authDB = require('../models/auth_schema');
const Review = require('../models/review_schema'); // Ensure correct path
const { verifyToken } = require('../middleware/verifyToken');
const reviewRouter = express.Router();

// Submit a review
reviewRouter.post('/submit', verifyToken, async (req, res) => {
  try {
    console.log("Incoming request body:", req.body); // Debugging

    const { message, rating } = req.body;

    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ Success: false, Message: 'Rating must be between 1 and 5.' });
    }

    const user = await authDB.findById(req.userId);
    if (!user) {
      return res.status(404).json({ Success: false, Message: 'User not found.' });
    }

    const review = new Review({
      userId: req.userId,
      name: user.name,
      message,
      rating,
    });

    await review.save();
    console.log("Review saved:", review); // Debugging

    res.status(201).json({
      Success: true,
      Message: 'Review submitted successfully.',
      Review: review,
    });
  } catch (error) {
    console.error("Error saving review:", error);
    res.status(500).json({ Success: false, Message: 'Internal Server Error' });
  }
});


// Get all reviews
reviewRouter.get('/all', async (req, res) => {
  try {
    const reviews = await Review.find()
      .populate('userId', 'name email') // Populate user details (name and email)
      .exec();
    
    if (reviews.length === 0) {
      return res.status(200).json({
        Success: true,
        Message: 'No reviews found.',
        Reviews: [],
      });
    }

    res.status(200).json({
      Success: true,
      Message: 'Reviews fetched successfully.',
      Reviews: reviews,
    });
  } catch (error) {
    res.status(500).json({ Success: false, Message: 'Internal Server Error' });
  }
});

module.exports = reviewRouter;
