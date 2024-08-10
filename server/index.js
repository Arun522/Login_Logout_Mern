const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect('mongodb://root1:root1@ac-jaqkd5n-shard-00-00.dntiqb2.mongodb.net:27017,ac-jaqkd5n-shard-00-01.dntiqb2.mongodb.net:27017,ac-jaqkd5n-shard-00-02.dntiqb2.mongodb.net:27017/?replicaSet=atlas-40v4k4-shard-0&ssl=true&authSource=admin&retryWrites=true&w=majority&appName=Cluster0');

// User Schema
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true },
  password: { 
    type: String, 
    required: true }
});

const User = mongoose.model('User', userSchema);

// Food Schema
const foodSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true 
},
  lastEatenDate: { 
    type: Date, 
    required: true },
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' }
});

const Food = mongoose.model('Food', foodSchema);

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ message: 'No token provided' });

  jwt.verify(token, 'your_jwt_secret', (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Failed to authenticate token' });
    req.userId = decoded.userId;
    next();
  });
};

// Register route
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ token, userId: user._id });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Add food route (protected)
app.post('/api/foods', verifyToken, async (req, res) => {
  try {
    const { name, lastEatenDate } = req.body;
    const food = new Food({ 
      name, 
      lastEatenDate: new Date(lastEatenDate), 
      user: req.userId 
    });
    await food.save();
    res.status(201).json(food);
  } catch (error) {
    res.status(500).json({ message: 'Error adding food' });
  }
});

// Get all foods for a user (protected)
app.get('/api/foods', verifyToken, async (req, res) => {
  try {
    const foods = await Food.find({ user: req.userId });
    res.json(foods);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching foods' });
  }
});

// Update last eaten date for a food (protected)
app.put('/api/foods/:id', verifyToken, async (req, res) => {
  try {
    const { lastEatenDate } = req.body;
    const food = await Food.findOneAndUpdate(
      { _id: req.params.id, user: req.userId },
      { lastEatenDate: new Date(lastEatenDate) },
      { new: true }
    );
    if (!food) {
      return res.status(404).json({ message: 'Food not found' });
    }
    res.json(food);
  } catch (error) {
    res.status(500).json({ message: 'Error updating food' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));