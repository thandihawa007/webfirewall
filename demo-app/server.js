// 1. Loads environment variables via dotenv at the very top
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
require('dotenv').config();

const express = require('express');
const cors = require('cors');

// 2. Database connection
const connectDB = require('./config/db');

// 3. WAF reusable middleware
const waf = require('../waf-core');

// 4. Application routes
const demoRoutes = require('./routes/demo');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 4000;

// Connect to MongoDB
connectDB();

// Setup core middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Apply WAF middleware GLOBALLY BEFORE any route is mounted
app.use(waf);

// Mount application routes
app.use('/demo', demoRoutes);
app.use('/admin', adminRoutes);

// Catch-all for undefined routes
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Start the server listening on process.env.PORT
app.listen(PORT, () => {
  console.log(`[WAF Server] Server listening on port ${PORT}`);
});
