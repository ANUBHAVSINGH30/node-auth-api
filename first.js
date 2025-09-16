const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();

app.use(express.json());

require('dotenv').config();

const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect(MONGO_URL);

const User = mongoose.model('Users', {
  name: String,
  email: String,
  password: String
});


app.post("/signup", async function(req, res) {
  const { name, email, password } = req.body;

  try {
    const userExists = await User.findOne({ email: email });
    if (userExists) {
      return res.status(400).send("User already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name: name,
      email: email,
      password: hashedPassword
    });

    await newUser.save();

    res.json({
      "msg": "User created successfully"
    });

  } catch (error) {
    console.error(error);
    res.status(500).send("An error occurred on the server.");
  }
});


app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(404).json({ msg: "User not found." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials." });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET, // Using the hardcoded secret
      { expiresIn: '1h' }
    );

    res.json({
      msg: "Logged in successfully!",
      token: token
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Server error during login." });
  }
});

// This middleware will act as our "security guard"
const authMiddleware = (req, res, next) => {
  // 1. Get the token from the request header
  const authHeader = req.headers.authorization;

  // 2. Check if the token exists and is in the correct format
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(403).json({ msg: 'Authorization denied.' });
  }

  const token = authHeader.split(' ')[1];

  // 3. Verify the token
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Optional: Add the decoded user data to the request
    next(); // If token is valid, proceed to the next step (the route handler)
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid.' });
  }
};

app.get("/users", authMiddleware, async function(req, res) {
  try {
    const allUsers = await User.find({}, '-password');
    res.json(allUsers);
  } catch (error) {
    res.status(500).json({ msg: "Failed to retrieve users" });
  }
});


app.listen(3000, () => {
    console.log("Server is running on port 3000");
});
