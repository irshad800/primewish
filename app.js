require('dotenv').config();
const express = require("express");  // Fixed typo
const app = express();
const mongoose = require("mongoose");
const cors = require('cors');
const authRouter = require("./routes/auth_routes");
const reviewRouter = require("./routes/review_routes");
const path = require("path");
const newsletterRoutes = require('./routes/newsletter_routes');
// Enable CORS
app.use(cors());

// Database Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log("Database Connected"))
    .catch((error) => console.log("Database Connection Error:", error));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use("/api/auth", authRouter);
app.use("/api/review", reviewRouter);
app.use('/api/newsletter', newsletterRoutes);
app.use(express.static(path.join(__dirname, 'public')));

// Simple Routes
app.get("/", (req, res) => res.send("hello"));
app.get("/add", (req, res) => res.send("hi"));
app.get("/a", (req, res) => res.send("a"));
app.get("/b", (req, res) => res.send("b"));

// Start Server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
