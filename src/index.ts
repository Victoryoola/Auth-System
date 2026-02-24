import express, { Application } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import { Server } from 'http';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import path from 'path';

// Services
import { DeviceRegistry } from './services/DeviceRegistry';
import { RiskEngine } from './services/RiskEngine';
import { SessionManager } from './services/SessionManager';
import { AuthService } from './services/AuthService';
import { StepUpVerifier } from './services/StepUpVerifier';
import { AuditLogger } from './services/AuditLogger';

// Middleware
import { createAccessControlMiddleware } from './middleware/accessControl';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';

// Routes
import { createAuthRoutes } from './routes/authRoutes';
import { createStepUpRoutes } from './routes/stepUpRoutes';
import { createDeviceRoutes } from './routes/deviceRoutes';
import { createSessionRoutes } from './routes/sessionRoutes';
import { createAuditRoutes } from './routes/auditRoutes';

// Load environment variables
dotenv.config();

const app: Application = express();
const PORT = process.env.PORT || 3000;

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

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Stricter rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 auth requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Health check endpoint
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
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
  const riskEngine = new RiskEngine(deviceRegistry);
  const sessionManager = new SessionManager(privateKey, publicKey);
  const authService = new AuthService(deviceRegistry, riskEngine, sessionManager);
  const stepUpVerifier = new StepUpVerifier(sessionManager);
  const auditLogger = new AuditLogger();

  // Create access control middleware
  const accessControl = createAccessControlMiddleware(sessionManager);

  return {
    deviceRegistry,
    riskEngine,
    sessionManager,
    authService,
    stepUpVerifier,
    auditLogger,
    accessControl,
  };
}

// Initialize services and routes
const services = initializeServices();

// API Routes
app.use('/api/auth', authLimiter, createAuthRoutes(services.authService, services.sessionManager));
app.use('/api/auth/step-up', createStepUpRoutes(services.stepUpVerifier, services.accessControl));
app.use('/api/devices', createDeviceRoutes(services.deviceRegistry, services.sessionManager, services.accessControl));
app.use('/api/sessions', createSessionRoutes(services.sessionManager, services.accessControl));
app.use('/api/audit-logs', createAuditRoutes(services.auditLogger, services.accessControl));

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
