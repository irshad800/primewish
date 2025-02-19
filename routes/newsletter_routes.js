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
    // Save the email to the database
    const newSubscription = new Newsletter({ email });
    await newSubscription.save();

    // Send confirmation email
    const mailOptions = {
      from: 'irshadvp800@gmail.com',
      to: email,
      subject: 'Newsletter Subscription Confirmation',
      text: 'Thank you for subscribing to our newsletter!',
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ message: 'Failed to send confirmation email.' });
      }
      res.status(200).json({ message: 'Subscription successful, confirmation email sent.' });
    });
  } catch (error) {
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
        from: 'irshadvp800@gmail.com',
        to: email,  // Send to one subscriber at a time
        subject: subject,
        text: message,
      };

      // Sending mail for each subscriber
      await transporter.sendMail(mailOptions);
    }

    res.status(200).json({ message: 'Newsletter sent successfully to all subscribers.' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to send newsletter. Try again later.' });
  }
});

module.exports = router;
