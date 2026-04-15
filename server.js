require('dotenv').config({ path:'./.env'});

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const URI = process.env.URI;
console.log("ENV FILE LOADED:",process.env.URI);

//  MongoDB Connection
mongoose.connect(URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

//  User Model
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Compare password
userSchema.methods.comparePassword = function(password) {
  return bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

//  Register API
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const existing = await User.findOne({ username });

    if (existing) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const user = new User({ username, password });
    await user.save();

    res.json({ message: 'User registered successfully' });

  } catch (err) {
    res.status(500).json({ message: 'Registration error' });
  }
});


//  Login API

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({ token });

  } catch (err) {
    res.status(500).json({ message: 'Login error' });
  }
});


//  Auth Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}


//  Protected Route

app.get('/dashboard', authenticateToken, (req, res) => {
  res.json({
    message: `Welcome ${req.user.username}`
  });
});


//  Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});