const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

/**
 * User Schema - Stores basic and additional user information
 */
const userSchema = new mongoose.Schema({
  // User's personal information
  firstname: {
    type: String,
    required: [true, 'First name is required'],
    trim: true
  },
  lastname: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true
  },
  companyname: {
    type: String,
    required: [true, 'Company name is required'],
    unique: true,
    trim: true
  },
  domain: {
    type: String,
    required: [true, 'Domain name is required'],
    unique: true,
    lowercase: true,
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true
  },
  phone: {
    type: String,
    trim: true
  },
  stock_ticker_symbol: {
    type: String,
    required: [true, 'Stock ticker symbol is required'],
    uppercase: true,
    trim: true
  },
  password: {
    type: String,
    required: [true, 'Password is required']
  },
  
  // User's role or type (if needed, for example: admin, customer, etc.)
  role: {
    type: String,
    enum: ['admin', 'customer'],
    default: 'customer'
  },

  // Status tracking (active/inactive)
  status: {
    type: String,
    enum: ['active', 'inactive'],
    default: 'active'
  },

  // Timestamps for record tracking
  lastLogin: {
    type: Date
  },

  createdAt: {
    type: Date,
    default: Date.now
  },

  updatedAt: {
    type: Date
  }
}, 
{ 
  timestamps: true 
});

// Encrypt the password before saving the user
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  // Hash password using bcrypt before saving
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Add a method to compare entered password with the stored hashed password
userSchema.methods.comparePassword = async function(password) {
  return bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', userSchema);
