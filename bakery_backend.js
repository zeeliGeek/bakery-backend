// ====================================
// server.js
// ====================================
const app = require('./src/app');
const config = require('./src/config');
const logger = require('./src/utils/logger');
const connectDB = require('./src/config/database');
const { connectRedis } = require('./src/config/redis');

const PORT = config.PORT || 3000;

async function startServer() {
  try {
    // Connect to MongoDB
    await connectDB();
    logger.info('Connected to MongoDB');

    // Connect to Redis
    await connectRedis();
    logger.info('Connected to Redis');

    // Start server
    const server = app.listen(PORT, () => {
      logger.info(`Server running on port ${PORT} in ${config.NODE_ENV} mode`);
    });

    // Initialize Socket.IO
    const io = require('./src/socket')(server);
    app.set('io', io);

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, shutting down gracefully');
      server.close(() => {
        logger.info('Process terminated');
      });
    });

    process.on('unhandledRejection', (err) => {
      logger.error('Unhandled Rejection:', err);
      server.close(() => {
        process.exit(1);
      });
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

// ====================================
// src/app.js
// ====================================
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');

const config = require('./config');
const routes = require('./routes');
const { errorHandler, notFound } = require('./middleware/error.middleware');
const rateLimitMiddleware = require('./middleware/rate-limit.middleware');
const securityMiddleware = require('./middleware/security.middleware');
const loggingMiddleware = require('./middleware/logging.middleware');

const app = express();

// Trust proxy
app.set('trust proxy', 1);

// Security middleware
app.use(helmet());
app.use(cors({
  origin: config.CORS_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
app.use(rateLimitMiddleware);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Data sanitization
app.use(mongoSanitize());

// Compression middleware
app.use(compression());

// Logging middleware
if (config.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
  app.use(loggingMiddleware);
}

// Security headers
app.use(securityMiddleware);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: config.NODE_ENV
  });
});

// API routes
app.use('/api', routes);

// 404 handler
app.use(notFound);

// Global error handler
app.use(errorHandler);

module.exports = app;

// ====================================
// src/config/index.js
// ====================================
require('dotenv').config();

module.exports = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: process.env.PORT || 3000,
  
  // Database
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/bakery',
  
  // JWT
  JWT_SECRET: process.env.JWT_SECRET || 'your-secret-key',
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret',
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '15m',
  JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  
  // Redis
  REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
  
  // AWS S3
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  AWS_REGION: process.env.AWS_REGION || 'us-east-1',
  AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
  
  // Stripe
  STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
  STRIPE_WEBHOOK_SECRET: process.env.STRIPE_WEBHOOK_SECRET,
  
  // Firebase
  FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID,
  FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY,
  FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL,
  
  // SMS
  TWILIO_ACCOUNT_SID: process.env.TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN: process.env.TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER: process.env.TWILIO_PHONE_NUMBER,
  
  // Email
  EMAIL_HOST: process.env.EMAIL_HOST,
  EMAIL_PORT: process.env.EMAIL_PORT || 587,
  EMAIL_USER: process.env.EMAIL_USER,
  EMAIL_PASS: process.env.EMAIL_PASS,
  
  // CORS
  CORS_ORIGIN: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
  
  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100
};

// ====================================
// src/config/database.js
// ====================================
const mongoose = require('mongoose');
const config = require('./index');
const logger = require('../utils/logger');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(config.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    logger.info(`MongoDB Connected: ${conn.connection.host}`);
    
    // Handle connection events
    mongoose.connection.on('error', (err) => {
      logger.error('MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      logger.info('MongoDB reconnected');
    });

    return conn;
  } catch (error) {
    logger.error('Database connection failed:', error);
    process.exit(1);
  }
};

module.exports = connectDB;

// ====================================
// src/config/redis.js
// ====================================
const { createClient } = require('redis');
const config = require('./index');
const logger = require('../utils/logger');

let redisClient;

const connectRedis = async () => {
  try {
    redisClient = createClient({
      url: config.REDIS_URL
    });

    redisClient.on('error', (err) => {
      logger.error('Redis Client Error:', err);
    });

    redisClient.on('connect', () => {
      logger.info('Connected to Redis');
    });

    redisClient.on('disconnect', () => {
      logger.warn('Redis disconnected');
    });

    await redisClient.connect();
    return redisClient;
  } catch (error) {
    logger.error('Redis connection failed:', error);
    throw error;
  }
};

const getRedisClient = () => {
  if (!redisClient) {
    throw new Error('Redis client not initialized');
  }
  return redisClient;
};

module.exports = {
  connectRedis,
  getRedisClient
};

// ====================================
// src/config/aws.js
// ====================================
const AWS = require('aws-sdk');
const config = require('./index');

// Configure AWS
AWS.config.update({
  accessKeyId: config.AWS_ACCESS_KEY_ID,
  secretAccessKey: config.AWS_SECRET_ACCESS_KEY,
  region: config.AWS_REGION
});

const s3 = new AWS.S3();

module.exports = {
  s3,
  AWS
};

// ====================================
// src/config/stripe.js
// ====================================
const Stripe = require('stripe');
const config = require('./index');

const stripe = Stripe(config.STRIPE_SECRET_KEY);

module.exports = stripe;

// ====================================
// src/config/firebase.js
// ====================================
const admin = require('firebase-admin');
const config = require('./index');

if (config.FIREBASE_PROJECT_ID) {
  const serviceAccount = {
    projectId: config.FIREBASE_PROJECT_ID,
    privateKey: config.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    clientEmail: config.FIREBASE_CLIENT_EMAIL
  };

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

module.exports = admin;

// ====================================
// src/models/User.js
// ====================================
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    unique: true,
    match: [/^\+?[1-9]\d{1,14}$/, 'Please enter a valid phone number']
  },
  email: {
    type: String,
    lowercase: true,
    sparse: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  addresses: [{
    title: {
      type: String,
      required: true,
      trim: true
    },
    address: {
      type: String,
      required: true,
      trim: true
    },
    landmark: {
      type: String,
      trim: true
    },
    city: {
      type: String,
      required: true,
      trim: true
    },
    state: {
      type: String,
      required: true,
      trim: true
    },
    zipCode: {
      type: String,
      required: true,
      trim: true
    },
    isDefault: {
      type: Boolean,
      default: false
    }
  }],
  favorites: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product'
  }],
  fcmToken: {
    type: String
  },
  role: {
    type: String,
    enum: ['customer', 'admin'],
    default: 'customer'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date
  }
}, {
  timestamps: true
});

// Indexes
UserSchema.index({ phone: 1 }, { unique: true });
UserSchema.index({ email: 1 }, { sparse: true });

// Pre-save middleware to hash password
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Method to get public profile
UserSchema.methods.toPublicJSON = function() {
  const user = this.toObject();
  delete user.password;
  return user;
};

module.exports = mongoose.model('User', UserSchema);

// ====================================
// src/models/Category.js
// ====================================
const mongoose = require('mongoose');

const CategorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Category name is required'],
    unique: true,
    trim: true,
    maxlength: [50, 'Category name cannot exceed 50 characters']
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  image: {
    type: String,
    validate: {
      validator: function(v) {
        return !v || /^https?:\/\/.+/.test(v);
      },
      message: 'Please enter a valid URL'
    }
  },
  isActive: {
    type: Boolean,
    default: true
  },
  displayOrder: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Indexes
CategorySchema.index({ name: 1 }, { unique: true });
CategorySchema.index({ displayOrder: 1 });
CategorySchema.index({ isActive: 1 });

module.exports = mongoose.model('Category', CategorySchema);

// ====================================
// src/models/Product.js
// ====================================
const mongoose = require('mongoose');

const ProductSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Product name is required'],
    trim: true,
    maxlength: [100, 'Product name cannot exceed 100 characters']
  },
  description: {
    type: String,
    required: [true, 'Product description is required'],
    trim: true,
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Category',
    required: [true, 'Category is required']
  },
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: [0, 'Price cannot be negative']
  },
  discountPrice: {
    type: Number,
    min: [0, 'Discount price cannot be negative'],
    validate: {
      validator: function(v) {
        return !v || v < this.price;
      },
      message: 'Discount price must be less than original price'
    }
  },
  images: [{
    type: String,
    validate: {
      validator: function(v) {
        return /^https?:\/\/.+/.test(v);
      },
      message: 'Please enter a valid URL'
    }
  }],
  ingredients: [{
    type: String,
    trim: true
  }],
  nutritionalInfo: {
    calories: { type: Number, min: 0 },
    fat: { type: Number, min: 0 },
    carbs: { type: Number, min: 0 },
    protein: { type: Number, min: 0 }
  },
  isVegetarian: {
    type: Boolean,
    default: false
  },
  isVegan: {
    type: Boolean,
    default: false
  },
  allergens: [{
    type: String,
    enum: ['nuts', 'dairy', 'eggs', 'gluten', 'soy', 'shellfish']
  }],
  preparationTime: {
    type: Number,
    min: [1, 'Preparation time must be at least 1 minute']
  },
  isAvailable: {
    type: Boolean,
    default: true
  },
  isFeatured: {
    type: Boolean,
    default: false
  },
  ratings: {
    average: {
      type: Number,
      default: 0,
      min: 0,
      max: 5
    },
    count: {
      type: Number,
      default: 0,
      min: 0
    }
  },
  stock: {
    type: Number,
    default: 0,
    min: 0
  }
}, {
  timestamps: true
});

// Indexes
ProductSchema.index({ name: 'text', description: 'text' });
ProductSchema.index({ category: 1 });
ProductSchema.index({ isAvailable: 1 });
ProductSchema.index({ isFeatured: 1 });
ProductSchema.index({ price: 1 });
ProductSchema.index({ 'ratings.average': -1 });

// Virtual for effective price
ProductSchema.virtual('effectivePrice').get(function() {
  return this.discountPrice || this.price;
});

// Method to update ratings
ProductSchema.methods.updateRatings = async function() {
  const Review = mongoose.model('Review');
  const stats = await Review.aggregate([
    { $match: { product: this._id, isApproved: true } },
    {
      $group: {
        _id: '$product',
        averageRating: { $avg: '$rating' },
        totalReviews: { $sum: 1 }
      }
    }
  ]);

  if (stats.length > 0) {
    this.ratings.average = Math.round(stats[0].averageRating * 10) / 10;
    this.ratings.count = stats[0].totalReviews;
  } else {
    this.ratings.average = 0;
    this.ratings.count = 0;
  }

  await this.save();
};

module.exports = mongoose.model('Product', ProductSchema);

// ====================================
// src/models/Review.js
// ====================================
const mongoose = require('mongoose');

const ReviewSchema = new mongoose.Schema({
  product: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: [true, 'Product is required']
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User is required']
  },
  rating: {
    type: Number,
    required: [true, 'Rating is required'],
    min: [1, 'Rating must be at least 1'],
    max: [5, 'Rating cannot exceed 5']
  },
  comment: {
    type: String,
    trim: true,
    maxlength: [500, 'Comment cannot exceed 500 characters']
  },
  images: [{
    type: String,
    validate: {
      validator: function(v) {
        return /^https?:\/\/.+/.test(v);
      },
      message: 'Please enter a valid URL'
    }
  }],
  isApproved: {
    type: Boolean,
    default: true
  },
  likes: {
    type: Number,
    default: 0,
    min: 0
  }
}, {
  timestamps: true
});

// Indexes
ReviewSchema.index({ product: 1 });
ReviewSchema.index({ user: 1 });
ReviewSchema.index({ product: 1, user: 1 }, { unique: true });
ReviewSchema.index({ rating: 1 });
ReviewSchema.index({ isApproved: 1 });

// Post-save middleware to update product ratings
ReviewSchema.post('save', async function() {
  const Product = mongoose.model('Product');
  const product = await Product.findById(this.product);
  if (product) {
    await product.updateRatings();
  }
});

// Post-remove middleware to update product ratings
ReviewSchema.post('remove', async function() {
  const Product = mongoose.model('Product');
  const product = await Product.findById(this.product);
  if (product) {
    await product.updateRatings();
  }
});

module.exports = mongoose.model('Review', ReviewSchema);

// ====================================
// src/models/Order.js
// ====================================
const mongoose = require('mongoose');

const OrderSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User is required']
  },
  items: [{
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: true
    },
    name: {
      type: String,
      required: true
    },
    quantity: {
      type: Number,
      required: true,
      min: [1, 'Quantity must be at least 1']
    },
    price: {
      type: Number,
      required: true,
      min: [0, 'Price cannot be negative']
    }
  }],
  deliveryAddress: {
    address: {
      type: String,
      required: [true, 'Delivery address is required']
    },
    landmark: String,
    city: {
      type: String,
      required: [true, 'City is required']
    },
    state: {
      type: String,
      required: [true, 'State is required']
    },
    zipCode: {
      type: String,
      required: [true, 'Zip code is required']
    }
  },
  paymentDetails: {
    method: {
      type: String,
      enum: ['card', 'cash'],
      required: [true, 'Payment method is required']
    },
    transactionId: String,
    status: {
      type: String,
      enum: ['pending', 'completed', 'failed'],
      default: 'pending'
    }
  },
  orderStatus: {
    type: String,
    enum: ['placed', 'preparing', 'out_for_delivery', 'delivered', 'canceled'],
    default: 'placed'
  },
  subtotal: {
    type: Number,
    required: [true, 'Subtotal is required'],
    min: [0, 'Subtotal cannot be negative']
  },
  deliveryFee: {
    type: Number,
    default: 0,
    min: [0, 'Delivery fee cannot be negative']
  },
  taxes: {
    type: Number,
    required: [true, 'Taxes is required'],
    min: [0, 'Taxes cannot be negative']
  },
  discount: {
    type: Number,
    default: 0,
    min: [0, 'Discount cannot be negative']
  },
  total: {
    type: Number,
    required: [true, 'Total is required'],
    min: [0, 'Total cannot be negative']
  },
  isScheduled: {
    type: Boolean,
    default: false
  },
  scheduledDeliveryTime: Date,
  estimatedDeliveryTime: Date,
  deliveryPerson: {
    name: String,
    phone: String,
    location: {
      coordinates: {
        type: [Number],
        default: [0, 0]
      }
    }
  },
  specialInstructions: {
    type: String,
    maxlength: [500, 'Special instructions cannot exceed 500 characters']
  },
  statusHistory: [{
    status: {
      type: String,
      enum: ['placed', 'preparing', 'out_for_delivery', 'delivered', 'canceled']
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    notes: String
  }]
}, {
  timestamps: true
});

// Indexes
OrderSchema.index({ user: 1 });
OrderSchema.index({ orderStatus: 1 });
OrderSchema.index({ createdAt: -1 });
OrderSchema.index({ 'deliveryPerson.name': 1 });

// Pre-save middleware to update status history
OrderSchema.pre('save', function(next) {
  if (this.isModified('orderStatus') && !this.isNew) {
    this.statusHistory.push({
      status: this.orderStatus,
      timestamp: new Date()
    });
  }
  next();
});

// Method to calculate estimated delivery time
OrderSchema.methods.calculateEstimatedDelivery = function() {
  const now = new Date();
  const preparationTime = 30; // minutes
  const deliveryTime = 30; // minutes
  
  this.estimatedDeliveryTime = new Date(now.getTime() + (preparationTime + deliveryTime) * 60000);
};

module.exports = mongoose.model('Order', OrderSchema);

// ====================================
// src/models/Notification.js
// ====================================
const mongoose = require('mongoose');

const NotificationSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User is required']
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  message: {
    type: String,
    required: [true, 'Message is required'],
    trim: true,
    maxlength: [500, 'Message cannot exceed 500 characters']
  },
  type: {
    type: String,
    enum: ['order', 'promotion', 'system'],
    required: [true, 'Type is required']
  },
  referenceId: {
    type: mongoose.Schema.Types.ObjectId
  },
  isRead: {
    type: Boolean,
    default: false
  },
  data: {
    type: mongoose.Schema.Types.Mixed
  }
}, {
  timestamps: true
});

// Indexes
NotificationSchema.index({ user: 1, createdAt: -1 });
NotificationSchema.index({ user: 1, isRead: 1 });
NotificationSchema.index({ type: 1 });

module.exports = mongoose.model('Notification', NotificationSchema);

// ====================================
// src/models/Promotion.js
// ====================================
const mongoose = require('mongoose');

const PromotionSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  description: {
    type: String,
    required: [true, 'Description is required'],
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  image: {
    type: String,
    validate: {
      validator: function(v) {
        return !v || /^https?:\/\/.+/.test(v);
      },
      message: 'Please enter a valid URL'
    }
  },
  discountType: {
    type: String,
    enum: ['percentage', 'fixed'],
    required: [true, 'Discount type is required']
  },
  discountValue: {
    type: Number,
    required: [true, 'Discount value is required'],
    min: [0, 'Discount value cannot be negative']
  },
  code: {
    type: String,
    unique: true,
    uppercase: true,
    trim: true,
    match: [/^[A-Z0-9]{3,20}$/, 'Code must be 3-20 characters, letters and numbers only']
  },
  minimumOrderValue: {
    type: Number,
    default: 0,
    min: [0, 'Minimum order value cannot be negative']
  },
  startDate: {
    type: Date,
    required: [true, 'Start date is required']
  },
  endDate: {
    type: Date,
    required: [true, 'End date is required'],
    validate: {
      validator: function(v) {
        return v > this.startDate;
      },
      message: 'End date must be after start date'
    }
  },
  isActive: {
    type: Boolean,
    default: true
  },
  applicableProducts: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product'
  }],
  usageLimit: {
    type: Number,
    min: [1, 'Usage limit must be at least 1']
  },
  usedCount: {
    type: Number,
    default: 0,
    min: 0
  }
}, {
  timestamps: true
});

// Indexes
PromotionSchema.index({ code: 1 }, { unique: true });
PromotionSchema.index({ isActive: 1 });
PromotionSchema.index({ startDate: 1, endDate: 1 });

// Virtual to check if promotion is currently valid
PromotionSchema.virtual('isValid').get(function() {
  const now = new Date();
  return this.isActive && 
         this.startDate <= now && 
         this.endDate >= now &&
         (!this.usageLimit || this.usedCount < this.usageLimit);
});

module.exports = mongoose.model('Promotion', PromotionSchema);

// ====================================
// src/models/OTP.js
// ====================================
const mongoose = require('mongoose');

const OTPSchema = new mongoose.Schema({
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    match: [/^\+?[1-9]\d{1,14}$/, 'Please enter a valid phone number']
  },
  otp: {
    type: String,
    required: [true, 'OTP is required'],
    length: [6, 'OTP must be 6 digits']
  },
  type: {
    type: String,
    enum: ['registration', 'login', 'password_reset'],
    required: [true, 'OTP type is required']
  },
  isUsed: {
    type: Boolean,
    default: false
  },
  attempts: {
    type: Number,
    default: 0,
    max: [3, 'Maximum 3 attempts allowed']
  },
  expiresAt: {
    type: Date,
    default: Date.now,
    expires: 600 // 10 minutes
  }
}, {
  timestamps: true
});

// Indexes
OTPSchema.index({ phone: 1, type: 1 });
OTPSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('OTP', OTPSchema);

// ====================================
// src/models/index.js
// ====================================
const User = require('./User');
const Category = require('./Category');
const Product = require('./Product');
const Review = require('./Review');
const Order = require('./Order');
const Notification = require('./Notification');
const Promotion = require('./Promotion');
const OTP = require('./OTP');

module.exports = {
  User,
  Category,
  Product,
  Review,
  Order,
  Notification,
  Promotion,
  OTP
};

// ====================================
// src/utils/logger.js
// ====================================
const winston = require('winston');
const config = require('../config');

const logger = winston.createLogger({
  level: config.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'bakery-api' },
  transports: [
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: 'logs/app.log',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    })
  ]
});

if (config.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

module.exports = logger;

// ====================================
// src/utils/response.js
// ====================================
class ApiResponse {
  constructor(success, message, data = null, statusCode = 200) {
    this.success = success;
    this.message = message;
    this.data = data;
    this.statusCode = statusCode;
    this.timestamp = new Date().toISOString();
  }

  static success(res, message = 'Success', data = null, statusCode = 200) {
    const response = new ApiResponse(true, message, data, statusCode);
    return res.status(statusCode).json(response);
  }

  static error(res, message = 'Error', statusCode = 500, errors = null) {
    const response = new ApiResponse(false, message, null, statusCode);
    if (errors) response.errors = errors;
    return res.status(statusCode).json(response);
  }

  static created(res, message = 'Created successfully', data = null) {
    return this.success(res, message, data, 201);
  }

  static updated(res, message = 'Updated successfully', data = null) {
    return this.success(res, message, data, 200);
  }

  static deleted(res, message = 'Deleted successfully') {
    return this.success(res, message, null, 200);
  }

  static notFound(res, message = 'Resource not found') {
    return this.error(res, message, 404);
  }

  static badRequest(res, message = 'Bad request', errors = null) {
    return this.error(res, message, 400, errors);
  }

  static unauthorized(res, message = 'Unauthorized access') {
    return this.error(res, message, 401);
  }

  static forbidden(res, message = 'Access forbidden') {
    return this.error(res, message, 403);
  }

  static conflict(res, message = 'Resource conflict') {
    return this.error(res, message, 409);
  }

  static serverError(res, message = 'Internal server error') {
    return this.error(res, message, 500);
  }
}

module.exports = ApiResponse;

// ====================================
// src/utils/error.js
// ====================================
class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';

    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message, errors = null) {
    super(message, 400);
    this.errors = errors;
  }
}

class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404);
  }
}

class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized access') {
    super(message, 401);
  }
}

class ForbiddenError extends AppError {
  constructor(message = 'Access forbidden') {
    super(message, 403);
  }
}

class ConflictError extends AppError {
  constructor(message = 'Resource conflict') {
    super(message, 409);
  }
}

module.exports = {
  AppError,
  ValidationError,
  NotFoundError,
  UnauthorizedError,
  ForbiddenError,
  ConflictError
};

// ====================================
// src/utils/jwt.js
// ====================================
const jwt = require('jsonwebtoken');
const config = require('../config');

const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { userId, type: 'access' },
    config.JWT_SECRET,
    { expiresIn: config.JWT_EXPIRES_IN }
  );

  const refreshToken = jwt.sign(
    { userId, type: 'refresh' },
    config.JWT_REFRESH_SECRET,
    { expiresIn: config.JWT_REFRESH_EXPIRES_IN }
  );

  return { accessToken, refreshToken };
};

const verifyAccessToken = (token) => {
  return jwt.verify(token, config.JWT_SECRET);
};

const verifyRefreshToken = (token) => {
  return jwt.verify(token, config.JWT_REFRESH_SECRET);
};

const getTokenFromHeader = (authHeader) => {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.split(' ')[1];
};

module.exports = {
  generateTokens,
  verifyAccessToken,
  verifyRefreshToken,
  getTokenFromHeader
};

// ====================================
// src/utils/otp.js
// ====================================
const crypto = require('crypto');

const generateOTP = (length = 6) => {
  const digits = '0123456789';
  let otp = '';
  
  for (let i = 0; i < length; i++) {
    otp += digits[Math.floor(Math.random() * 10)];
  }
  
  return otp;
};

const generateSecureOTP = (length = 6) => {
  const buffer = crypto.randomBytes(length);
  let otp = '';
  
  for (let i = 0; i < length; i++) {
    otp += (buffer[i] % 10).toString();
  }
  
  return otp;
};

module.exports = {
  generateOTP,
  generateSecureOTP
};

// ====================================
// src/utils/pagination.js
// ====================================
const paginate = (query, options) => {
  const page = parseInt(options.page) || 1;
  const limit = parseInt(options.limit) || 10;
  const skip = (page - 1) * limit;

  return {
    ...query,
    skip,
    limit,
    page
  };
};

const getPaginationMeta = (total, page, limit) => {
  const totalPages = Math.ceil(total / limit);
  const hasNextPage = page < totalPages;
  const hasPrevPage = page > 1;

  return {
    total,
    page,
    limit,
    totalPages,
    hasNextPage,
    hasPrevPage,
    nextPage: hasNextPage ? page + 1 : null,
    prevPage: hasPrevPage ? page - 1 : null
  };
};

module.exports = {
  paginate,
  getPaginationMeta
};

// ====================================
// src/utils/constants.js
// ====================================
const ORDER_STATUS = {
  PLACED: 'placed',
  PREPARING: 'preparing',
  OUT_FOR_DELIVERY: 'out_for_delivery',
  DELIVERED: 'delivered',
  CANCELED: 'canceled'
};

const PAYMENT_STATUS = {
  PENDING: 'pending',
  COMPLETED: 'completed',
  FAILED: 'failed'
};

const USER_ROLES = {
  CUSTOMER: 'customer',
  ADMIN: 'admin'
};

const NOTIFICATION_TYPES = {
  ORDER: 'order',
  PROMOTION: 'promotion',
  SYSTEM: 'system'
};

const OTP_TYPES = {
  REGISTRATION: 'registration',
  LOGIN: 'login',
  PASSWORD_RESET: 'password_reset'
};

const DISCOUNT_TYPES = {
  PERCENTAGE: 'percentage',
  FIXED: 'fixed'
};

const PAYMENT_METHODS = {
  CARD: 'card',
  CASH: 'cash'
};

const ALLERGENS = [
  'nuts',
  'dairy', 
  'eggs',
  'gluten',
  'soy',
  'shellfish'
];

module.exports = {
  ORDER_STATUS,
  PAYMENT_STATUS,
  USER_ROLES,
  NOTIFICATION_TYPES,
  OTP_TYPES,
  DISCOUNT_TYPES,
  PAYMENT_METHODS,
  ALLERGENS
};

// ====================================
// src/utils/helpers.js
// ====================================
const crypto = require('crypto');

const calculateTax = (amount, taxRate = 0.18) => {
  return Math.round(amount * taxRate * 100) / 100;
};

const calculateDeliveryFee = (distance = 5, baseFee = 50) => {
  if (distance <= 3) return baseFee;
  return baseFee + Math.ceil((distance - 3) * 10);
};

const generateOrderNumber = () => {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substr(2, 5);
  return `ORD-${timestamp}-${random}`.toUpperCase();
};

const generatePromoCode = (length = 8) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < length; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
};

const slugify = (text) => {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^\w\-]+/g, '')
    .replace(/\-\-+/g, '-');
};

const isValidPhoneNumber = (phone) => {
  const phoneRegex = /^\+?[1-9]\d{1,14}$/;
  return phoneRegex.test(phone);
};

const isValidEmail = (email) => {
  const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
  return emailRegex.test(email);
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/[<>]/g, '');
};

const formatCurrency = (amount, currency = 'INR') => {
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency: currency
  }).format(amount);
};

const getDistanceFromCoords = (lat1, lon1, lat2, lon2) => {
  const R = 6371; // Radius of the earth in km
  const dLat = deg2rad(lat2 - lat1);
  const dLon = deg2rad(lon2 - lon1);
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  const d = R * c; // Distance in km
  return d;
};

const deg2rad = (deg) => {
  return deg * (Math.PI/180);
};

module.exports = {
  calculateTax,
  calculateDeliveryFee,
  generateOrderNumber,
  generatePromoCode,
  slugify,
  isValidPhoneNumber,
  isValidEmail,
  sanitizeInput,
  formatCurrency,
  getDistanceFromCoords
};

// ====================================
// src/utils/validators.js
// ====================================
const { isValidPhoneNumber, isValidEmail } = require('./helpers');

const validateRequired = (value, fieldName) => {
  if (!value || (typeof value === 'string' && !value.trim())) {
    throw new Error(`${fieldName} is required`);
  }
};

const validateEmail = (email) => {
  if (email && !isValidEmail(email)) {
    throw new Error('Please enter a valid email address');
  }
};

const validatePhone = (phone) => {
  if (!isValidPhoneNumber(phone)) {
    throw new Error('Please enter a valid phone number');
  }
};

const validatePassword = (password) => {
  if (!password || password.length < 6) {
    throw new Error('Password must be at least 6 characters long');
  }
};

const validateObjectId = (id, fieldName = 'ID') => {
  const mongoose = require('mongoose');
  if (!mongoose.Types.ObjectId.isValid(id)) {
    throw new Error(`Invalid ${fieldName}`);
  }
};

const validatePositiveNumber = (value, fieldName) => {
  if (isNaN(value) || value < 0) {
    throw new Error(`${fieldName} must be a positive number`);
  }
};

const validateRange = (value, min, max, fieldName) => {
  if (value < min || value > max) {
    throw new Error(`${fieldName} must be between ${min} and ${max}`);
  }
};

module.exports = {
  validateRequired,
  validateEmail,
  validatePhone,
  validatePassword,
  validateObjectId,
  validatePositiveNumber,
  validateRange
};
