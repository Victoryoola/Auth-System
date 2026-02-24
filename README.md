# Adaptive Risk-Based Authentication & Device Trust Engine (AADE)

A production-ready backend authentication security system that dynamically evaluates login risk signals and adjusts user access levels based on trust scores, device familiarity, and verification outcomes.

## Overview

AADE provides sophisticated risk-based authentication that adapts to user behavior and context. It evaluates multiple risk factors in real-time to assign trust levels to sessions, requiring additional verification only when necessary. This approach balances security with user experience.

## Key Features

### Authentication & Security
- Multi-factor authentication (MFA) with email/password
- Real-time risk scoring based on device, location, IP reputation, and behavioral signals
- Dynamic session trust levels: FULL_TRUST, LIMITED_TRUST, UNVERIFIED, HIGH_RISK
- Step-up authentication for privilege escalation
- JWT-based token management with RS256 signing
- Refresh token rotation for enhanced security
- Argon2id password hashing

### Device Management
- Device fingerprinting and recognition
- Device trust registry with TRUSTED/UNTRUSTED/PENDING states
- Device revocation with session invalidation
- Device metadata tracking (browser, OS, IP address)

### Session Management
- Stateless session design with Redis caching
- Multiple concurrent session support
- Session termination and management
- Trust level enforcement per endpoint

### Security & Monitoring
- Comprehensive audit logging for all security events
- Rate limiting on all endpoints
- CORS and Helmet security headers
- Input validation with express-validator
- Prometheus metrics for monitoring
- Health check endpoints

## Prerequisites

- Node.js 18+ or 20+
- PostgreSQL 14+
- Redis 6+
- npm or yarn

## Quick Start

```bash
# Clone the repository
git clone git@github.com:Victoryoola/Auth-System.git
cd authsystem

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
npm run migrate

# Start the development server
npm run dev
```

Visit http://localhost:3000/health to verify the server is running.

## Installation

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

Copy `.env.example` to `.env` and configure:

```bash
# Server Configuration
NODE_ENV=development
PORT=3000

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=aade_db
DB_USER=postgres
DB_PASSWORD=your_secure_password

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# JWT Configuration
JWT_ACCESS_SECRET=your_jwt_access_secret_here
JWT_REFRESH_SECRET=your_jwt_refresh_secret_here
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# Security Configuration
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### 3. Set Up Database

```bash
# Create PostgreSQL database
createdb aade_db

# Run migrations
npm run migrate
```

### 4. Start the Server

```bash
# Development mode with hot reload
npm run dev

# Production mode
npm run build
npm start
```

## Development

### Available Scripts

```bash
# Development
npm run dev              # Start development server with hot reload

# Testing
npm test                 # Run all tests
npm run test:watch       # Run tests in watch mode
npm run test:coverage    # Run tests with coverage report

# Code Quality
npm run lint             # Lint code
npm run lint:fix         # Fix linting issues
npm run format           # Format code with Prettier
npm run format:check     # Check code formatting

# Build
npm run build            # Build for production
npm start                # Start production server

# Database
npm run migrate          # Run database migrations
```

## Project Structure

```
adaptive-risk-auth-engine/
├── src/
│   ├── config/          # Configuration files (database, redis)
│   ├── controllers/     # API route controllers
│   ├── middleware/      # Express middleware (auth, error handling)
│   ├── models/          # Data models and database schemas
│   ├── routes/          # API route definitions
│   ├── services/        # Business logic services
│   ├── types/           # TypeScript type definitions
│   ├── utils/           # Utility functions
│   └── index.ts         # Application entry point
├── migrations/          # Database migration scripts
├── docs/                # Documentation
│   ├── api-reference.md
│   ├── integration-guide.md
│   ├── deployment-guide.md
│   ├── setup-guide.md
│   ├── database-schema.md
│   └── openapi.yaml
├── scripts/             # Utility scripts
└── tests/               # Test files
```

## Core Concepts

### Trust Levels

Sessions are assigned trust levels based on risk assessment:

- **FULL_TRUST**: Low risk, trusted device - full access to all operations
- **LIMITED_TRUST**: Moderate risk - restricted access to sensitive operations  
- **UNVERIFIED**: Elevated risk or unknown device - requires step-up authentication
- **HIGH_RISK**: High risk - minimal or read-only access

### Risk Factors

The risk engine evaluates multiple factors:

- Device familiarity (known vs. unknown devices)
- Geographic anomalies (unusual locations)
- IP reputation (VPN, proxy, known bad actors)
- Login velocity (rapid login attempts)
- Failed authentication attempts
- Behavioral patterns

### Step-Up Authentication

When a user attempts a sensitive operation with insufficient trust level, they can increase their session trust through step-up authentication:

1. User initiates step-up challenge (EMAIL_OTP, SMS_OTP, or AUTHENTICATOR_APP)
2. System sends verification code
3. User verifies with OTP
4. Session trust level is elevated to FULL_TRUST

## API Endpoints

### Authentication

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/auth/login` | POST | User login with email/password | No |
| `/auth/mfa/verify` | POST | Verify MFA code | No |
| `/auth/refresh` | POST | Refresh access token | No |
| `/auth/logout` | POST | Logout and terminate session | Yes |

### Step-Up Authentication

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/auth/step-up/initiate` | POST | Initiate verification challenge | Yes (requireVerified) |
| `/auth/step-up/verify` | POST | Verify OTP | No |
| `/auth/step-up/resend` | POST | Resend OTP | No |

### Device Management

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/devices` | GET | List user devices | Yes (requireVerified) |
| `/devices/:id/trust` | PUT | Update device trust status | Yes (requireVerified) |
| `/devices/:id` | DELETE | Revoke device | Yes (requireVerified) |

### Session Management

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/sessions` | GET | List active sessions | Yes (requireVerified) |
| `/sessions/:id` | DELETE | Terminate session | Yes (requireVerified) |

### Audit Logs

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/audit-logs` | GET | Retrieve audit logs | Yes (requireVerified) |

### Example: Login Flow

```bash
# 1. Login with credentials
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "deviceInfo": {
      "userAgent": "Mozilla/5.0...",
      "screenResolution": "1920x1080",
      "timezone": "America/New_York",
      "language": "en-US"
    }
  }'

# Response (if MFA not required):
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "trustLevel": "FULL_TRUST",
  "expiresIn": 900,
  "requiresMFA": false
}

# 2. Make authenticated requests
curl -X GET http://localhost:3000/devices \
  -H "Authorization: Bearer <access_token>"

# 3. Refresh token when expired
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

See the [API Reference](docs/api-reference.md) for detailed documentation and examples.

## Documentation

### Getting Started
- **[Setup Guide](docs/setup-guide.md)** - Installation, configuration, and initial setup
- **[Database Schema](docs/database-schema.md)** - Database structure, models, and migrations

### API Documentation
- **[API Reference](docs/api-reference.md)** - Complete REST API documentation with examples
- **[OpenAPI Specification](docs/openapi.yaml)** - OpenAPI 3.0 specification for API tools and code generation

### Integration
- **[Integration Guide](docs/integration-guide.md)** - How to integrate AADE into your application
  - Web application integration (React, Vue, Angular)
  - Mobile application integration (React Native, Flutter)
  - Backend-to-backend integration
  - Common scenarios and code examples
  - Client libraries and SDKs

### Deployment
- **[Deployment Guide](docs/deployment-guide.md)** - Production deployment instructions
  - Infrastructure requirements
  - Docker deployment with docker-compose
  - Kubernetes deployment with Helm
  - Cloud deployments (AWS ECS/EKS, GCP Cloud Run/GKE, Azure AKS)
  - Horizontal and vertical scaling
  - Monitoring, logging, and observability
  - Security hardening
  - Backup and disaster recovery

## Technology Stack

### Backend
- **Node.js** 18+ with TypeScript
- **Express.js** - Web framework
- **PostgreSQL** 14+ - Primary database
- **Redis** 6+ - Session caching and rate limiting

### Security
- **Argon2id** - Password hashing
- **jsonwebtoken** - JWT token management with RS256
- **Helmet** - Security headers
- **express-rate-limit** - Rate limiting
- **express-validator** - Input validation

### Monitoring & Observability
- **prom-client** - Prometheus metrics
- **Winston** - Structured logging

### Testing
- **Jest** - Testing framework
- **Supertest** - HTTP assertions
- **fast-check** - Property-based testing

## Security Features

### Authentication Security
- Argon2id password hashing with configurable cost
- JWT tokens signed with RS256 (asymmetric encryption)
- Refresh token rotation to prevent token replay attacks
- MFA support with TOTP/OTP
- Account lockout after failed attempts

### Network Security
- CORS configuration
- Helmet security headers (CSP, HSTS, X-Frame-Options, etc.)
- Rate limiting on all endpoints
- Input validation and sanitization

### Data Security
- Encrypted database connections (SSL/TLS)
- Secure Redis connections
- Environment variable management
- No sensitive data in logs

### Monitoring & Audit
- Comprehensive audit logging for all security events
- Failed authentication tracking
- Suspicious activity detection
- Real-time metrics and alerting

## Performance

### Optimizations
- Connection pooling for PostgreSQL
- Redis caching for session data
- Stateless design for horizontal scaling
- Efficient database indexes
- Async/await for non-blocking I/O

### Benchmarks
- Login: ~100-200ms (including risk evaluation)
- Token refresh: ~50-100ms
- Device lookup: ~20-50ms (cached)
- Risk evaluation: ~50-100ms

### Scaling
- Horizontal scaling: Add more application instances
- Database: Read replicas, connection pooling
- Redis: Cluster mode for high availability
- Load balancing: Round-robin or least-connections

## Deployment Options

### Docker
```bash
# Build image
docker build -t aade:latest .

# Run with docker-compose
docker-compose up -d
```

### Kubernetes
```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Scale deployment
kubectl scale deployment aade --replicas=5
```

### Cloud Platforms
- **AWS**: ECS, EKS, or Lambda with API Gateway
- **Google Cloud**: Cloud Run, GKE, or Cloud Functions
- **Azure**: Container Instances, AKS, or Azure Functions

See the [Deployment Guide](docs/deployment-guide.md) for detailed instructions.

## Monitoring

### Health Checks
- `GET /health` - Basic health check
- `GET /ready` - Readiness check (includes DB and Redis connectivity)

### Metrics
Prometheus metrics available at `/metrics`:
- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request latency
- `auth_attempts_total` - Authentication attempts
- `risk_evaluation_duration_seconds` - Risk evaluation latency
- `session_creation_total` - Session creations
- `token_refresh_total` - Token refreshes

### Logging
Structured JSON logging with Winston:
- Request/response logging
- Error logging with stack traces
- Security event logging
- Performance metrics

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `NODE_ENV` | Environment mode | `development` | No |
| `PORT` | Server port | `3000` | No |
| `DB_HOST` | PostgreSQL host | `localhost` | Yes |
| `DB_PORT` | PostgreSQL port | `5432` | No |
| `DB_NAME` | Database name | - | Yes |
| `DB_USER` | Database user | - | Yes |
| `DB_PASSWORD` | Database password | - | Yes |
| `REDIS_HOST` | Redis host | `localhost` | Yes |
| `REDIS_PORT` | Redis port | `6379` | No |
| `REDIS_PASSWORD` | Redis password | - | No |
| `JWT_ACCESS_SECRET` | JWT access token secret | - | Yes |
| `JWT_REFRESH_SECRET` | JWT refresh token secret | - | Yes |
| `JWT_ACCESS_EXPIRY` | Access token expiry | `15m` | No |
| `JWT_REFRESH_EXPIRY` | Refresh token expiry | `7d` | No |
| `BCRYPT_ROUNDS` | Argon2 cost parameter | `12` | No |
| `RATE_LIMIT_WINDOW_MS` | Rate limit window | `900000` | No |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window | `100` | No |
| `LOG_LEVEL` | Logging level | `info` | No |

See `.env.example` for a complete configuration template.

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### Test Coverage

The project maintains high test coverage:
- Unit tests for all services
- Integration tests for API endpoints
- Property-based tests for critical logic
- Mock implementations for external dependencies

### Test Structure

```
src/
├── services/
│   ├── AuthService.ts
│   ├── AuthService.test.ts
│   ├── RiskEngine.ts
│   └── RiskEngine.test.ts
└── index.test.ts
```

## Contributing

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `npm test`
5. Run linting: `npm run lint`
6. Commit your changes: `git commit -am 'Add new feature'`
7. Push to the branch: `git push origin feature/my-feature`
8. Submit a pull request

### Code Style

- Follow TypeScript best practices
- Use ESLint and Prettier for code formatting
- Write tests for new features
- Document public APIs
- Keep functions small and focused

## Troubleshooting

### Common Issues

**Database connection errors**
```bash
# Check PostgreSQL is running
pg_isready -h localhost -p 5432

# Verify credentials in .env
```

**Redis connection errors**
```bash
# Check Redis is running
redis-cli ping

# Should return: PONG
```

**Port already in use**
```bash
# Change PORT in .env or kill the process
lsof -ti:3000 | xargs kill -9
```

**Migration errors**
```bash
# Reset database and re-run migrations
dropdb aade_db
createdb aade_db
npm run migrate
```

See the [Setup Guide](docs/setup-guide.md) for more troubleshooting tips.

## Roadmap

- [ ] WebAuthn/FIDO2 support
- [ ] Biometric authentication
- [ ] Advanced anomaly detection with ML
- [ ] GraphQL API
- [ ] Admin dashboard
- [ ] Multi-tenancy support
- [ ] OAuth2/OIDC provider
- [ ] Passwordless authentication

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/aade/issues)
- **Email**: support@example.com

## Acknowledgments

Built with modern security best practices and inspired by industry-leading authentication systems.
