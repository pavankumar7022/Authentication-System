require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const PORT = process.env.PORT||3000;
const app = express();
app.use(express.json());

// ENV
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || "mysecret";
const URI = process.env.URI;

//  DB CONNECTION 
mongoose.connect(URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('DB Error:', err));

//  USER MODEL 
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String
});

// hash password
userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
});

// compare password
userSchema.methods.comparePassword = function (password) {
  return bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

//  REGISTER 
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existing = await User.findOne({ username });

    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    const user = new User({ username, password });
    await user.save();

    res.json({ message: "User registered successfully" });

  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Registration error" });
  }
});

//  LOGIN 
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({
      message: "Login successful",
      token
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Login error" });
  }
});

//  AUTH MIDDLEWARE 
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }

    req.user = user;
    next();
  });
}

//  PROTECTED ROUTE 
app.get('/dashboard', authenticateToken, (req, res) => {
  res.json({
    message: `Welcome ${req.user.username} `
  });
});

// PROFILE ROUTE 
app.get('/profile', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

//  SERVER 
app.listen(PORT, () => {
  console.log(` Server running at http://localhost:${PORT}`);
});