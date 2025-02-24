const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');
const Newsletter = require('../models/newsletter');

// Email transporter setup using Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail', // Use your email service
  auth: {
    user: process.env.EMAIL_ID,
    pass: process.env.EMAIL_APP_PASSWORD, 
  },
});

// Route to subscribe to the newsletter
router.post('/subscribe', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }

  try {
    // Check if email already exists in the database
    const existingSubscriber = await Newsletter.findOne({ email });
    if (existingSubscriber) {
      return res.status(400).json({ message: 'You are already subscribed to our newsletter.' });
    }

    // Save the email to the database
    const newSubscription = new Newsletter({ email });
    await newSubscription.save();

    // Send confirmation email
    const mailOptions = {
      from: process.env.EMAIL_ID,
      to: email,
      subject: 'Newsletter Subscription Confirmation',
      text: 'Thank you for subscribing to our newsletter!',
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Email Sending Error:', error);
        return res.status(500).json({ message: 'Subscription successful, but failed to send confirmation email.' });
      }
      res.status(200).json({ message: 'Subscription successful, confirmation email sent.' });
    });
  } catch (error) {
    console.error('Subscription Error:', error);
    res.status(500).json({ message: 'Failed to subscribe. Try again later.' });
  }
});

// Route to send the newsletter to all subscribers
router.post('/send-newsletter', async (req, res) => {
  const { subject, message } = req.body;

  if (!subject || !message) {
    return res.status(400).json({ message: 'Subject and message are required.' });
  }

  try {
    // Retrieve all subscribed email addresses
    const subscribers = await Newsletter.find({});
    const emailAddresses = subscribers.map(subscriber => subscriber.email);

    if (emailAddresses.length === 0) {
      return res.status(400).json({ message: 'No subscribers to send the newsletter to.' });
    }

    // Send the newsletter to each subscriber individually
    for (let email of emailAddresses) {
      const mailOptions = {
        from: process.env.EMAIL_ID,
        to: email,
        subject: subject,
        text: message,
      };

      try {
        await transporter.sendMail(mailOptions);
      } catch (emailError) {
        console.error(`Failed to send email to ${email}:`, emailError);
      }
    }

    res.status(200).json({ message: 'Newsletter sent successfully to all subscribers.' });
  } catch (error) {
    console.error('Newsletter Sending Error:', error);
    res.status(500).json({ message: 'Failed to send newsletter. Try again later.' });
  }
});

module.exports = router;
