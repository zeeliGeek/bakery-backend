# Bakery Shop Backend API Architecture

## Table of Contents
1. [System Architecture Overview](#system-architecture-overview)
2. [Database Schema Design](#database-schema-design)
3. [API Endpoints](#api-endpoints)
4. [Authentication & Security](#authentication--security)
5. [Data Flow Patterns](#data-flow-patterns)
6. [Scalability Considerations](#scalability-considerations)
7. [Deployment Strategy](#deployment-strategy)

## System Architecture Overview

### Tech Stack
- **Runtime Environment**: Node.js
- **Web Framework**: Express.js
- **Database**: MongoDB with Mongoose ODM
- **Authentication**: JWT (JSON Web Tokens)
- **Image Storage**: AWS S3 (for product images)
- **Caching**: Redis
- **Payment Processing**: Stripe Integration
- **Notification Services**: Firebase Cloud Messaging (FCM)
- **Order Tracking**: WebSockets (Socket.io)

### High-Level Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Mobile Client  │◄────┤   API Gateway   │◄────┤  Load Balancer  │
└─────────────────┘     └────────┬────────┘     └────────┬────────┘
                                 │                       │
                                 ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Redis Cache    │◄────┤  Node.js API    │────►│   MongoDB       │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                 ┌───────────────┼───────────────┐
                 ▼               ▼               ▼
        ┌────────────┐   ┌────────────┐   ┌────────────┐
        │ Auth Svc   │   │ Order Svc  │   │ Product Svc│
        └────────────┘   └────────────┘   └────────────┘
                                │
                                ▼
                        ┌────────────────┐
                        │External Services│
                        │ - Payments     │
                        │ - Notifications│
                        │ - Maps/Tracking│
                        └────────────────┘
```

## Database Schema Design

### User Schema
```javascript
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  phone: { type: String, required: true, unique: true },
  email: { type: String, lowercase: true, sparse: true },
  password: { type: String, required: true },
  addresses: [{
    title: { type: String, required: true }, // e.g., "Home", "Work"
    address: { type: String, required: true },
    landmark: { type: String },
    city: { type: String, required: true },
    state: { type: String, required: true },
    zipCode: { type: String, required: true },
    isDefault: { type: Boolean, default: false }
  }],
  favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  fcmToken: { type: String }, // For push notifications
  role: { type: String, enum: ['customer', 'admin'], default: 'customer' },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });
```

### Category Schema
```javascript
const CategorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String },
  image: { type: String }, // URL to image in S3
  isActive: { type: Boolean, default: true },
  displayOrder: { type: Number, default: 0 } // For ordering in UI
}, { timestamps: true });
```

### Product Schema
```javascript
const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
  price: { type: Number, required: true },
  discountPrice: { type: Number },
  images: [{ type: String }], // URLs to images in S3
  ingredients: [{ type: String }],
  nutritionalInfo: {
    calories: { type: Number },
    fat: { type: Number },
    carbs: { type: Number },
    protein: { type: Number }
  },
  isVegetarian: { type: Boolean, default: false },
  allergens: [{ type: String }],
  preparationTime: { type: Number }, // in minutes
  isAvailable: { type: Boolean, default: true },
  isFeatured: { type: Boolean, default: false },
  ratings: {
    average: { type: Number, default: 0 },
    count: { type: Number, default: 0 }
  }
}, { timestamps: true });
```

### Review Schema
```javascript
const ReviewSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String },
  images: [{ type: String }], // Optional review images
  isApproved: { type: Boolean, default: true },
  likes: { type: Number, default: 0 }
}, { timestamps: true });
```

### Order Schema
```javascript
const OrderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    quantity: { type: Number, required: true },
    price: { type: Number, required: true } // Price at time of order
  }],
  deliveryAddress: {
    address: { type: String, required: true },
    landmark: { type: String },
    city: { type: String, required: true },
    state: { type: String, required: true },
    zipCode: { type: String, required: true }
  },
  paymentDetails: {
    method: { type: String, enum: ['card', 'cash'], required: true },
    transactionId: { type: String }, // For card payments
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' }
  },
  orderStatus: {
    type: String, 
    enum: ['placed', 'preparing', 'out_for_delivery', 'delivered', 'canceled'],
    default: 'placed'
  },
  subtotal: { type: Number, required: true },
  deliveryFee: { type: Number, default: 0 },
  taxes: { type: Number, required: true },
  discount: { type: Number, default: 0 },
  total: { type: Number, required: true },
  isScheduled: { type: Boolean, default: false },
  scheduledDeliveryTime: { type: Date }, // If scheduled for later
  estimatedDeliveryTime: { type: Date }, // For immediate orders
  deliveryPerson: {
    name: { type: String },
    phone: { type: String },
    location: {
      coordinates: {
        type: [Number], // [longitude, latitude]
        default: [0, 0]
      }
    }
  },
  specialInstructions: { type: String }
}, { timestamps: true });
```

### Notification Schema
```javascript
const NotificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['order', 'promotion', 'system'], required: true },
  referenceId: { type: mongoose.Schema.Types.ObjectId }, // Order ID or other reference
  isRead: { type: Boolean, default: false }
}, { timestamps: true });
```

### Promotion Schema
```javascript
const PromotionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String }, // URL to banner image
  discountType: { type: String, enum: ['percentage', 'fixed'], required: true },
  discountValue: { type: Number, required: true },
  code: { type: String, unique: true },
  minimumOrderValue: { type: Number, default: 0 },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  isActive: { type: Boolean, default: true },
  applicableProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  usageLimit: { type: Number } // How many times it can be used
}, { timestamps: true });
```

## API Endpoints

### Authentication Endpoints

```
POST /api/v1/auth/register
POST /api/v1/auth/verify-otp
POST /api/v1/auth/login
POST /api/v1/auth/refresh-token
POST /api/v1/auth/send-otp
POST /api/v1/auth/reset-password
```

### User Management

```
GET    /api/v1/users/profile
PUT    /api/v1/users/profile
GET    /api/v1/users/addresses
POST   /api/v1/users/addresses
PUT    /api/v1/users/addresses/:id
DELETE /api/v1/users/addresses/:id
POST   /api/v1/users/fcm-token
```

### Product Management

```
GET    /api/v1/categories
GET    /api/v1/categories/:id/products
GET    /api/v1/products
GET    /api/v1/products/featured
GET    /api/v1/products/popular
GET    /api/v1/products/:id
GET    /api/v1/products/search
```

### Favorites Management

```
GET    /api/v1/favorites
POST   /api/v1/favorites/:productId
DELETE /api/v1/favorites/:productId
```

### Review Management

```
GET    /api/v1/products/:id/reviews
POST   /api/v1/products/:id/reviews
PUT    /api/v1/reviews/:id
DELETE /api/v1/reviews/:id
```

### Order Management

```
POST   /api/v1/orders
GET    /api/v1/orders
GET    /api/v1/orders/:id
POST   /api/v1/orders/:id/cancel
GET    /api/v1/orders/:id/track
```

### Payment Processing

```
POST   /api/v1/payments/create-intent
POST   /api/v1/payments/confirm
POST   /api/v1/payments/webhook
```

### Notifications

```
GET    /api/v1/notifications
PUT    /api/v1/notifications/:id/read
DELETE /api/v1/notifications/:id
```

### Promotions

```
GET    /api/v1/promotions
POST   /api/v1/promotions/apply/:code
```

### Admin Endpoints

```
POST   /api/v1/admin/products
PUT    /api/v1/admin/products/:id
DELETE /api/v1/admin/products/:id
POST   /api/v1/admin/categories
PUT    /api/v1/admin/categories/:id
DELETE /api/v1/admin/categories/:id
GET    /api/v1/admin/orders
PUT    /api/v1/admin/orders/:id/status
POST   /api/v1/admin/promotions
PUT    /api/v1/admin/promotions/:id
DELETE /api/v1/admin/promotions/:id
```

## Authentication & Security

### Authentication Flow

1. **User Registration**:
   - User provides only name and phone number
   - System generates an OTP and sends it to the phone number
   - User submits OTP for verification
   - Upon successful verification, account is created and user is authenticated

2. **JWT Implementation**:
   - After authentication, two tokens are issued:
     - Access token (short-lived, 15-30 minutes)
     - Refresh token (longer-lived, 7-14 days)
   - Access token is sent in Authorization header: `Bearer <token>`
   - Refresh token is stored as HTTP-only secure cookie

3. **Token Refresh Mechanism**:
   - When access token expires, client uses refresh token to get a new pair
   - Refresh tokens are single-use (revoked after each use)

### Security Measures

```javascript
// Middleware for JWT validation
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }
  
  const token = authHeader.split(' ')[1];
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token.' });
  }
};

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again after 15 minutes'
});

// OTP rate limiting (to prevent SMS bombing)
const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each phone to 3 OTP requests per hour
  keyGenerator: (req) => req.body.phone || req.ip,
  message: 'Too many OTP requests, please try again later'
});
```

### Additional Security Measures

1. **Data Validation**:
   - Use Joi/Yup for request validation before processing
   - Sanitize inputs to prevent NoSQL injection

2. **CORS Configuration**:
   - Restrict cross-origin requests to trusted domains

3. **HTTP Security Headers**:
   - Implement Helmet.js to set security-related HTTP headers

4. **API Request Logging**:
   - Use Morgan for HTTP request logging
   - Implement Winston for application logging

5. **HTTPS Enforcement**:
   - Force all connections to use HTTPS

6. **Production Best Practices**:
   - Hide error stack traces in production
   - Set up proper NODE_ENV configurations

## Data Flow Patterns


### Authentication Flow

```mermaid
sequenceDiagram
    Client->>API: Register with name & phone
    API->>SMS Service: Send OTP to phone
    SMS Service-->>User: Receive SMS with OTP
    User->>Client: Enter OTP
    Client->>API: Submit OTP for verification
    API->>Database: Verify OTP
    Database-->>API: OTP valid
    API->>Database: Create user account
    API->>Client: Return JWT tokens
    Client->>API: Proceed to app home screen
```

### Order Creation Flow

```mermaid
sequenceDiagram
    Client->>API: POST /api/v1/orders
    API->>Validation: Validate order data
    Validation->>Inventory: Check product availability
    Inventory-->>Validation: Availability confirmed
    Validation->>Payment: Process payment
    Payment-->>Validation: Payment successful
    Validation->>Database: Create order record
    Database-->>API: Order created
    API->>Notification: Send order confirmation
    Notification-->>Client: Push notification
    API-->>Client: Order details response
```

### Order Tracking Flow
```
1. Order is placed (orderStatus = 'placed')
2. Kitchen confirms and starts preparation (orderStatus = 'preparing')
3. Delivery person is assigned
4. Order is picked up (orderStatus = 'out_for_delivery')
5. WebSocket connection provides real-time delivery tracking
6. Order is delivered (orderStatus = 'delivered')
7. Push notification is sent at each status change
```

## Scalability Considerations

### Database Indexing Strategy

```javascript
// User indexes
UserSchema.index({ phone: 1 }, { unique: true });

// Product indexes
ProductSchema.index({ name: 'text', description: 'text' });
ProductSchema.index({ category: 1 });
ProductSchema.index({ isAvailable: 1 });
ProductSchema.index({ isFeatured: 1 });

// Order indexes
OrderSchema.index({ user: 1 });
OrderSchema.index({ orderStatus: 1 });
OrderSchema.index({ createdAt: -1 });

// OTP indexes
OTPSchema.index({ phone: 1 });
OTPSchema.index({ createdAt: 1 }, { expireAfterSeconds: 600 }); // TTL index
```

### Caching Strategy

```javascript
// Redis caching for product listings
const getProducts = async (req, res) => {
  const cacheKey = `products:${JSON.stringify(req.query)}`;
  
  // Check if data exists in cache
  const cachedData = await redisClient.get(cacheKey);
  if (cachedData) {
    return res.json(JSON.parse(cachedData));
  }
  
  // If not in cache, fetch from database
  const products = await Product.find(queryFilters)
    .sort(sortOptions)
    .skip(skip)
    .limit(limit);
    
  // Store in cache for 10 minutes
  await redisClient.setEx(cacheKey, 600, JSON.stringify(products));
  
  return res.json(products);
};
```

### Horizontal Scaling

1. **Stateless API Design**:
   - No server-side sessions
   - JWT for authentication
   - File uploads directed to S3

2. **Load Balancing**:
   - Use Nginx or AWS ELB for distributing traffic
   - Implement sticky sessions for WebSocket connections

3. **Database Scaling**:
   - MongoDB replica sets for redundancy
   - Consider sharding for very large datasets

4. **Microservices Considerations**:
   - Split authentication, orders, and products into separate services
   - Use message queues (RabbitMQ/SQS) for inter-service communication

## Deployment Strategy

### Container-Based Deployment

```dockerfile
FROM node:16-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "server.js"]
```

### CI/CD Pipeline

```yaml
# Sample GitHub Actions workflow
name: Deploy Bakery API

on:
  push:
    branches: [ main ]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Node.js
      uses: actions/setup-node@v2
      with:
        node-version: '16'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Run tests
      run: npm test
      
    - name: Build Docker image
      run: docker build -t bakery-api .
      
    - name: Push to container registry
      # Push to AWS ECR or similar service
      
    - name: Deploy to production
      # Deploy to ECS/EKS or similar service
```

### Environment Configuration

```
# .env.example
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/bakery
JWT_SECRET=your_jwt_secret_key
JWT_REFRESH_SECRET=your_refresh_token_secret
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1
AWS_S3_BUCKET=bakery-images
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret
REDIS_URL=redis://localhost:6379
FCM_SERVER_KEY=your_fcm_server_key
SMS_PROVIDER_API_KEY=your_sms_service_key
```
