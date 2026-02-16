# Adaptive Risk-Based Authentication & Device Trust Engine (AADE)

A backend-driven authentication security system that dynamically evaluates login risk signals and adjusts user access levels based on trust scores, device familiarity, and verification outcomes.

## Features

- Multi-factor authentication with email/password and optional MFA
- Real-time risk scoring based on device, location, IP reputation, and behavioral signals
- Dynamic session trust levels (FULL_TRUST, LIMITED_TRUST, UNVERIFIED, HIGH_RISK)
- Device recognition and trust registry
- Step-up authentication for privilege escalation
- Comprehensive audit logging and security monitoring
- Token-based session management with refresh token rotation
- Rate limiting and attack prevention

## Prerequisites

- Node.js 18+ and npm
- PostgreSQL 14+
- Redis 6+

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Copy `.env.example` to `.env` and configure your environment variables:
   ```bash
   cp .env.example .env
   ```

4. Set up the database (migrations will be added in task 2)

## Development

Start the development server:
```bash
npm run dev
```

## Testing

Run all tests:
```bash
npm test
```

Run tests in watch mode:
```bash
npm run test:watch
```

Run tests with coverage:
```bash
npm run test:coverage
```

## Linting and Formatting

Lint code:
```bash
npm run lint
```

Fix linting issues:
```bash
npm run lint:fix
```

Format code:
```bash
npm run format
```

Check formatting:
```bash
npm run format:check
```

## Build

Build for production:
```bash
npm run build
```

Start production server:
```bash
npm start
```

## Project Structure

```
src/
├── services/       # Business logic services
├── models/         # Data models and database schemas
├── controllers/    # API route controllers
├── middleware/     # Express middleware
├── utils/          # Utility functions
├── types/          # TypeScript type definitions
├── config/         # Configuration files
└── index.ts        # Application entry point
```

## API Documentation

API documentation will be available at `/api-docs` once implemented.

## Security

- All passwords are hashed using Argon2id
- JWT tokens signed with RS256
- Rate limiting on all endpoints
- CORS and Helmet security headers
- Input validation on all API requests
- Comprehensive audit logging

## License

MIT
