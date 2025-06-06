bakery-backend/
├── src/
│   ├── config/
│   │   ├── database.js - Done
│   │   ├── redis.js - Done
│   │   ├── aws.js - Done
│   │   ├── stripe.js - Done
│   │   ├── firebase.js - Done 
│   │   └── index.js - Done
│   ├── controllers/
│   │   ├── auth.controller.js
│   │   ├── user.controller.js
│   │   ├── product.controller.js
│   │   ├── category.controller.js
│   │   ├── order.controller.js
│   │   ├── payment.controller.js
│   │   ├── review.controller.js
│   │   ├── notification.controller.js
│   │   ├── promotion.controller.js
│   │   └── admin.controller.js
│   ├── models/
│   │   ├── User.js - Done
│   │   ├── Product.js - Done
│   │   ├── Category.js - Done
│   │   ├── Order.js - Done
│   │   ├── Review.js - Done
│   │   ├── Notification.js - Done
│   │   ├── Promotion.js - Done
│   │   ├── OTP.js - Done
│   │   └── index.js - Done
│   ├── routes/
│   │   ├── v1/
│   │   │   ├── auth.routes.js
│   │   │   ├── user.routes.js
│   │   │   ├── product.routes.js
│   │   │   ├── category.routes.js
│   │   │   ├── order.routes.js
│   │   │   ├── payment.routes.js
│   │   │   ├── review.routes.js
│   │   │   ├── notification.routes.js
│   │   │   ├── promotion.routes.js
│   │   │   ├── admin.routes.js
│   │   │   └── index.js
│   │   └── index.js
│   ├── services/
│   │   ├── auth.service.js - Done
│   │   ├── user.service.js - Done
│   │   ├── product.service.js - Done
│   │   ├── category.service.js - Done
│   │   ├── order.service.js - Done
│   │   ├── payment.service.js - Done
│   │   ├── review.service.js - Done
│   │   ├── notification.service.js - Done
│   │   ├── promotion.service.js - Done
│   │   ├── email.service.js - Done
│   │   ├── sms.service.js - Done
│   │   ├── upload.service.js - Done
│   │   ├── cache.service.js - Done
│   │   └── socket.service.js - Done
│   ├── middleware/
│   │   ├── auth.middleware.js
│   │   ├── validation.middleware.js
│   │   ├── error.middleware.js 
│   │   ├── rate-limit.middleware.js 
│   │   ├── upload.middleware.js
│   │   ├── cors.middleware.js 
│   │   ├── security.middleware.js 
│   │   └── logging.middleware.js 
│   ├── validations/
│   │   ├── auth.validation.js
│   │   ├── user.validation.js 
│   │   ├── product.validation.js
│   │   ├── category.validation.js
│   │   ├── order.validation.js
│   │   ├── payment.validation.js
│   │   ├── review.validation.js
│   │   ├── notification.validation.js
│   │   ├── promotion.validation.js
│   │   └── index.js
│   ├── utils/
│   │   ├── logger.js - Done
│   │   ├── response.js - Done
│   │   ├── error.js - Done
│   │   ├── helpers.js - Done
│   │   ├── constants.js - Done
│   │   ├── jwt.js - Done
│   │   ├── otp.js - Done
│   │   ├── pagination.js - Done
│   │   └── validators.js - Done
│   ├── workers/
│   │   ├── notification.worker.js
│   │   ├── order.worker.js
│   │   └── cleanup.worker.js
│   ├── jobs/
│   │   ├── email.job.js
│   │   ├── sms.job.js
│   │   └── order-reminder.job.js
│   ├── database/
│   │   ├── seeders/
│   │   │   ├── category.seeder.js
│   │   │   ├── product.seeder.js
│   │   │   ├── user.seeder.js
│   │   │   └── index.js
│   │   └── migrations/
│   │       ├── 001_create_indexes.js
│   │       └── 002_add_fields.js
│   ├── socket/
│   │   ├── handlers/
│   │   │   ├── order.handler.js
│   │   │   ├── delivery.handler.js
│   │   │   └── notification.handler.js
│   │   └── index.js
│   └── app.js
├── docs/
│   ├── api/
│   │   ├── swagger.yaml
│   │   └── postman/
│   ├── deployment/
│   │   ├── docker/
│   │   ├── kubernetes/
│   │   └── aws/
│   └── README.md
├── scripts/
│   ├── build.sh
│   ├── deploy.sh
│   ├── seed.js
│   ├── backup.js
│   └── cleanup.js
├── logs/
│   ├── access.log
│   ├── error.log
│   └── app.log
├── uploads/
│   └── temp/
├── .env.example
├── .env.development
├── .env.production
├── .gitignore
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
├── package.json
├── package-lock.json
├── server.js
├── README.md
└── CHANGELOG.md