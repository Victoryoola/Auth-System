import express, { Application } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import { Server } from 'http';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import path from 'path';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';

// Services
import { DeviceRegistry } from './services/DeviceRegistry';
import { RiskEngine } from './services/RiskEngine';
import { SessionManager } from './services/SessionManager';
import { AuthService } from './services/AuthService';
import { StepUpVerifier } from './services/StepUpVerifier';
import { AuditLogger } from './services/AuditLogger';
import { AccountService } from './services/AccountService';
import { MetricsService } from './services/MetricsService';
import { HealthCheckService } from './services/HealthCheckService';

// Middleware
import { createAccessControlMiddleware } from './middleware/accessControl';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { createMetricsMiddleware } from './middleware/metricsMiddleware';

// Routes
import { createAuthRoutes } from './routes/authRoutes';
import { createStepUpRoutes } from './routes/stepUpRoutes';
import { createDeviceRoutes } from './routes/deviceRoutes';
import { createSessionRoutes } from './routes/sessionRoutes';
import { createAuditRoutes } from './routes/auditRoutes';
import { createAccountRoutes } from './routes/accountRoutes';
import { createMetricsRoutes } from './routes/metricsRoutes';
import { createHealthRoutes } from './routes/healthRoutes';

// Load environment variables
dotenv.config();

const app: Application = express();
const PORT = process.env.PORT || 3000;

// Load OpenAPI specification
const openApiPath = path.join(__dirname, '../docs/openapi.yaml');
const swaggerDocument = YAML.load(openApiPath);

// Security middleware
app.use(helmet());

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400, // 24 hours
};
app.use(cors(corsOptions));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Initialize metrics service early
const metricsService = new MetricsService();

// Metrics middleware (track all API requests)
app.use(createMetricsMiddleware(metricsService));

// Rate limiting with metrics tracking
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    metricsService.recordRateLimitTrigger(req.path);
    res.status(429).json({
      error: 'rate_limit_exceeded',
      message: 'Too many requests from this IP, please try again later.',
    });
  },
});
app.use('/api/', limiter);

// Stricter rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 auth requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    metricsService.recordRateLimitTrigger('/api/auth');
    res.status(429).json({
      error: 'rate_limit_exceeded',
      message: 'Too many authentication attempts, please try again later.',
    });
  },
});

// Initialize services
function initializeServices() {
  // Load RSA keys for JWT signing
  const privateKeyPath = process.env.JWT_PRIVATE_KEY_PATH || path.join(__dirname, '../keys/private.key');
  const publicKeyPath = process.env.JWT_PUBLIC_KEY_PATH || path.join(__dirname, '../keys/public.key');

  let privateKey: string;
  let publicKey: string;

  try {
    privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    publicKey = fs.readFileSync(publicKeyPath, 'utf8');
  } catch (error) {
    console.warn('JWT keys not found, using default keys for development');
    // In production, these should be loaded from secure storage
    privateKey = process.env.JWT_PRIVATE_KEY || '';
    publicKey = process.env.JWT_PUBLIC_KEY || '';
  }

  // Initialize service instances
  const deviceRegistry = new DeviceRegistry();
  const riskEngine = new RiskEngine(deviceRegistry, metricsService);
  const sessionManager = new SessionManager(privateKey, publicKey);
  const authService = new AuthService(deviceRegistry, riskEngine, sessionManager, metricsService);
  const stepUpVerifier = new StepUpVerifier(sessionManager);
  const auditLogger = new AuditLogger();
  const accountService = new AccountService();
  const healthCheckService = new HealthCheckService();

  // Create access control middleware
  const accessControl = createAccessControlMiddleware(sessionManager);

  return {
    deviceRegistry,
    riskEngine,
    sessionManager,
    authService,
    stepUpVerifier,
    auditLogger,
    accountService,
    accessControl,
    metricsService,
    healthCheckService,
  };
}

// Initialize services and routes
const services = initializeServices();

// Health check routes (before other routes, no rate limiting)
app.use('/', createHealthRoutes(services.healthCheckService));

// Swagger UI documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'AADE API Documentation',
}));

// API Routes
app.use('/api/auth', authLimiter, createAuthRoutes(services.authService, services.sessionManager));
app.use('/api/auth/step-up', createStepUpRoutes(services.stepUpVerifier, services.accessControl));
app.use('/api/devices', createDeviceRoutes(services.deviceRegistry, services.sessionManager, services.accessControl));
app.use('/api/sessions', createSessionRoutes(services.sessionManager, services.accessControl));
app.use('/api/audit-logs', createAuditRoutes(services.auditLogger, services.accessControl));
app.use('/api/account', createAccountRoutes(services.accountService));

// Metrics endpoint (for Prometheus scraping)
app.use('/metrics', createMetricsRoutes(services.metricsService));

// 404 handler for undefined routes
app.use(notFoundHandler);

// Global error handler (must be last)
app.use(errorHandler);

let server: Server | null = null;

// Start server only if not in test environment
if (process.env.NODE_ENV !== 'test') {
  server = app.listen(PORT, () => {
    console.log(`AADE server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

export { app, server };
export default app;
