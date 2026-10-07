const mongoose = require('mongoose');

/**
 * Connects to MongoDB using MONGO_URI from environment variables.
 * Logs clear diagnostic messages on both success and failure.
 */
const connectDB = async () => {
  const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/waf-demo';

  try {
    await mongoose.connect(mongoURI);
    console.log(`[Database] Successfully connected to MongoDB at ${mongoURI}`);
  } catch (error) {
    console.error(`[Database] Connection Error: Could not connect to MongoDB at ${mongoURI}`);
    console.error(`[Database] Error Details: ${error.message}`);
    console.error('[Database] Verify that your MongoDB service is running (e.g. mongod or Windows service "MongoDB").');
  }
};

module.exports = connectDB;
