# AADE API Reference

## Overview

The Adaptive Risk-Based Authentication & Device Trust Engine (AADE) provides a RESTful API for authentication, device management, session management, and audit logging. All endpoints use JSON for request and response bodies.

**Base URL**: `http://localhost:3000` (configurable via PORT environment variable)

**API Version**: 1.0.0

## Table of Contents

- [Authentication](#authentication)
- [Authentication Endpoints](#authentication-endpoints)
- [Step-Up Authentication](#step-up-authentication)
- [Device Management](#device-management)
- [Session Management](#session-management)
- [Audit Logs](#audit-logs)
- [Error Responses](#error-responses)
- [Rate Limiting](#rate-limiting)

---

## Authentication

Most endpoints require authentication using a Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

### Trust Levels

Sessions are assigned trust levels based on risk assessment:

- **FULL_TRUST**: Low risk, trusted device - full access to all operations
- **LIMITED_TRUST**: Moderate risk - restricted access to sensitive operations
- **UNVERIFIED**: Elevated risk or unknown device - requires step-up authentication for sensitive operations
- **HIGH_RISK**: High risk - minimal or read-only access

### Access Requirements

- **requireVerified**: Requires UNVERIFIED, LIMITED_TRUST, or FULL_TRUST (blocks HIGH_RISK)
- **requireLimitedTrust**: Requires LIMITED_TRUST or FULL_TRUST
- **requireFullTrust**: Requires FULL_TRUST only

---

## Authentication Endpoints

### POST /auth/login

Authenticate a user with email and password.

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "deviceInfo": {
    "userAgent": "Mozilla/5.0...",
    "screenResolution": "1920x1080",
    "timezone": "America/New_York",
    "language": "en-US"
  }
}
```

**Success Response** (200 OK):
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "trustLevel": "FULL_TRUST",
  "expiresIn": 900,
  "requiresMFA": false
}
```

**MFA Required Response** (200 OK):
```json
{
  "requiresMFA": true,
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "message": "MFA verification required"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid input (missing fields, invalid email format)
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: Account locked
- `429 Too Many Requests`: Rate limit exceeded

**Example**:
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "deviceInfo": {
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "screenResolution": "1920x1080",
      "timezone": "America/New_York",
      "language": "en-US"
    }
  }'
```

---

### POST /auth/mfa/verify

Verify MFA code after initial authentication.

**Request Body**:
```json
{
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "mfaCode": "123456",
  "deviceInfo": {
    "userAgent": "Mozilla/5.0...",
    "screenResolution": "1920x1080",
    "timezone": "America/New_York",
    "language": "en-US"
  }
}
```

**Success Response** (200 OK):
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "trustLevel": "FULL_TRUST",
  "expiresIn": 900
}
```

**Error Responses**:
- `400 Bad Request`: Invalid input
- `401 Unauthorized`: Invalid MFA code
- `429 Too Many Requests`: Rate limit exceeded

---

### POST /auth/refresh

Refresh an expired access token using a refresh token.

**Request Body**:
```json
{
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Success Response** (200 OK):
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 900
}
```

**Error Responses**:
- `400 Bad Request`: Missing refresh token
- `401 Unauthorized`: Invalid or expired refresh token
- `403 Forbidden`: Token replay detected (all user sessions invalidated)

**Example**:
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

---

### POST /auth/logout

Terminate the current session.

**Authentication**: Required (Bearer token)

**Request Body**:
```json
{
  "sessionId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Success Response** (200 OK):
```json
{
  "message": "Logged out successfully"
}
```

**Error Responses**:
- `400 Bad Request`: Missing session ID
- `401 Unauthorized`: Invalid or expired token
- `404 Not Found`: Session not found

---

## Step-Up Authentication

### POST /auth/step-up/initiate

Initiate a step-up verification challenge to increase session trust level.

**Authentication**: Required (requireVerified - blocks HIGH_RISK)

**Request Body**:
```json
{
  "method": "EMAIL_OTP"
}
```

**Supported Methods**:
- `EMAIL_OTP`: Send OTP via email
- `SMS_OTP`: Send OTP via SMS
- `AUTHENTICATOR_APP`: Use authenticator app (TOTP)

**Success Response** (200 OK):
```json
{
  "challengeId": "550e8400-e29b-41d4-a716-446655440000",
  "method": "EMAIL_OTP",
  "expiresAt": "2024-01-15T10:20:00Z",
  "attemptsRemaining": 3
}
```

**Error Responses**:
- `400 Bad Request`: Invalid method
- `401 Unauthorized`: Invalid or expired token
- `429 Too Many Requests`: Rate limit exceeded (5 challenges per hour)

**Example**:
```bash
curl -X POST http://localhost:3000/auth/step-up/initiate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{
    "method": "EMAIL_OTP"
  }'
```

---

### POST /auth/step-up/verify

Verify OTP for step-up authentication.

**Authentication**: Not required (challenge ID is sufficient)

**Request Body**:
```json
{
  "challengeId": "550e8400-e29b-41d4-a716-446655440000",
  "otp": "123456"
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "newTrustLevel": "FULL_TRUST",
  "message": "Verification successful"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid input or expired challenge
- `401 Unauthorized`: Invalid OTP
- `429 Too Many Requests`: Maximum attempts exceeded

**Example**:
```bash
curl -X POST http://localhost:3000/auth/step-up/verify \
  -H "Content-Type: application/json" \
  -d '{
    "challengeId": "550e8400-e29b-41d4-a716-446655440000",
    "otp": "123456"
  }'
```

---

### POST /auth/step-up/resend

Resend OTP for an existing challenge.

**Authentication**: Not required (challenge ID is sufficient)

**Request Body**:
```json
{
  "challengeId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Success Response** (200 OK):
```json
{
  "message": "OTP resent successfully",
  "expiresAt": "2024-01-15T10:30:00Z"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid challenge ID
- `404 Not Found`: Challenge not found or expired
- `429 Too Many Requests`: Rate limit exceeded

---

## Device Management

### GET /devices

List all devices for the authenticated user.

**Authentication**: Required (requireVerified)

**Success Response** (200 OK):
```json
{
  "devices": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "identity": "a1b2c3d4e5f6...",
      "trustStatus": "TRUSTED",
      "revoked": false,
      "firstSeen": "2024-01-01T10:00:00Z",
      "lastSeen": "2024-01-15T09:30:00Z",
      "metadata": {
        "deviceType": "desktop",
        "browser": "Chrome 120.0",
        "operatingSystem": "Windows 10",
        "lastIpAddress": "192.168.1.100"
      }
    }
  ]
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or expired token
- `403 Forbidden`: Insufficient trust level

**Example**:
```bash
curl -X GET http://localhost:3000/devices \
  -H "Authorization: Bearer <access_token>"
```

---

### PUT /devices/:id/trust

Update device trust status.

**Authentication**: Required (requireVerified)

**URL Parameters**:
- `id`: Device ID (UUID)

**Request Body**:
```json
{
  "trustStatus": "TRUSTED"
}
```

**Valid Trust Statuses**:
- `TRUSTED`: Device is trusted
- `UNTRUSTED`: Device is not trusted
- `PENDING`: Trust status pending

**Success Response** (200 OK):
```json
{
  "message": "Device trust status updated",
  "device": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "trustStatus": "TRUSTED"
  }
}
```

**Error Responses**:
- `400 Bad Request`: Invalid trust status
- `401 Unauthorized`: Invalid or expired token
- `403 Forbidden`: Cannot modify another user's device
- `404 Not Found`: Device not found

---

### DELETE /devices/:id

Revoke a device and invalidate all its sessions.

**Authentication**: Required (requireVerified)

**URL Parameters**:
- `id`: Device ID (UUID)

**Success Response** (200 OK):
```json
{
  "message": "Device revoked successfully",
  "sessionsInvalidated": 2
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or expired token
- `403 Forbidden`: Cannot revoke another user's device
- `404 Not Found`: Device not found

**Example**:
```bash
curl -X DELETE http://localhost:3000/devices/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

## Session Management

### GET /sessions

List all active sessions for the authenticated user.

**Authentication**: Required (requireVerified)

**Success Response** (200 OK):
```json
{
  "sessions": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "trustLevel": "FULL_TRUST",
      "deviceIdentity": "a1b2c3d4e5f6...",
      "createdAt": "2024-01-15T09:00:00Z",
      "lastActivity": "2024-01-15T09:30:00Z",
      "ipAddress": "192.168.1.100",
      "current": true
    },
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "trustLevel": "LIMITED_TRUST",
      "deviceIdentity": "b2c3d4e5f6a7...",
      "createdAt": "2024-01-14T15:00:00Z",
      "lastActivity": "2024-01-15T08:00:00Z",
      "ipAddress": "10.0.0.50",
      "current": false
    }
  ]
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or expired token
- `403 Forbidden`: Insufficient trust level

**Example**:
```bash
curl -X GET http://localhost:3000/sessions \
  -H "Authorization: Bearer <access_token>"
```

---

### DELETE /sessions/:id

Terminate a specific session.

**Authentication**: Required (requireVerified)

**URL Parameters**:
- `id`: Session ID (UUID)

**Success Response** (200 OK):
```json
{
  "message": "Session terminated successfully"
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or expired token
- `403 Forbidden`: Cannot terminate another user's session
- `404 Not Found`: Session not found

**Example**:
```bash
curl -X DELETE http://localhost:3000/sessions/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer <access_token>"
```

---

## Audit Logs

### GET /audit-logs

Retrieve audit logs for the authenticated user with optional filters.

**Authentication**: Required (requireVerified)

**Query Parameters**:
- `eventType` (optional): Filter by event type (e.g., LOGIN_ATTEMPT, RISK_EVALUATION)
- `startDate` (optional): Filter logs after this date (ISO 8601 format)
- `endDate` (optional): Filter logs before this date (ISO 8601 format)
- `limit` (optional): Maximum number of logs to return (default: 100, max: 1000)
- `offset` (optional): Pagination offset (default: 0)

**Success Response** (200 OK):
```json
{
  "logs": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": "2024-01-15T09:30:00Z",
      "eventType": "LOGIN_ATTEMPT",
      "success": true,
      "details": {
        "ipAddress": "192.168.1.100",
        "deviceIdentity": "a1b2c3d4e5f6...",
        "trustLevel": "FULL_TRUST"
      }
    },
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "timestamp": "2024-01-15T09:29:00Z",
      "eventType": "RISK_EVALUATION",
      "success": true,
      "details": {
        "riskScore": 15,
        "trustLevel": "FULL_TRUST",
        "factors": {
          "deviceFamiliarity": 0,
          "geographicAnomaly": 0,
          "ipReputation": 0,
          "loginVelocity": 0,
          "failedAttempts": 0
        }
      }
    }
  ],
  "total": 2,
  "limit": 100,
  "offset": 0
}
```

**Event Types**:
- `LOGIN_ATTEMPT`: User login attempt
- `RISK_EVALUATION`: Risk score calculation
- `DEVICE_CHANGE`: Device trust status change
- `SUSPICIOUS_ACTIVITY`: Suspicious activity detected
- `STEP_UP_ATTEMPT`: Step-up authentication attempt

**Error Responses**:
- `400 Bad Request`: Invalid query parameters
- `401 Unauthorized`: Invalid or expired token
- `403 Forbidden`: Insufficient trust level

**Example**:
```bash
curl -X GET "http://localhost:3000/audit-logs?eventType=LOGIN_ATTEMPT&limit=50" \
  -H "Authorization: Bearer <access_token>"
```

---

## Error Responses

All error responses follow a consistent format:

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {}
}
```

### Common Error Codes

**400 Bad Request**:
- `invalid_input`: Missing or invalid request parameters
- `validation_error`: Input validation failed

**401 Unauthorized**:
- `invalid_credentials`: Email or password incorrect
- `invalid_token`: Access token invalid or expired
- `token_expired`: Access token has expired (use refresh token)
- `invalid_mfa`: MFA code incorrect
- `invalid_otp`: OTP incorrect or expired

**403 Forbidden**:
- `account_locked`: Account temporarily locked due to failed attempts
- `insufficient_trust`: Session trust level insufficient for operation
- `access_denied`: User not authorized to access resource

**404 Not Found**:
- `resource_not_found`: Requested resource does not exist

**429 Too Many Requests**:
- `rate_limit_exceeded`: Too many requests, retry after specified time

**500 Internal Server Error**:
- `internal_error`: Unexpected server error

### Error Response Examples

**Invalid Credentials**:
```json
{
  "error": "invalid_credentials",
  "message": "Invalid email or password"
}
```

**Account Locked**:
```json
{
  "error": "account_locked",
  "message": "Account locked due to multiple failed login attempts",
  "details": {
    "lockoutUntil": "2024-01-15T10:00:00Z"
  }
}
```

**Rate Limit Exceeded**:
```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests, please try again later",
  "details": {
    "retryAfter": 300
  }
}
```

---

## Rate Limiting

The API implements rate limiting to prevent abuse:

### Global Rate Limits

- **Authentication endpoints** (`/auth/*`): 100 requests per 15 minutes per IP
- **Step-up initiation**: 5 challenges per hour per user
- **Step-up verification**: 3 attempts per challenge
- **Other endpoints**: 1000 requests per 15 minutes per IP

### Rate Limit Headers

All responses include rate limit information:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705315200
```

### Handling Rate Limits

When rate limited, the API returns:

**Response** (429 Too Many Requests):
```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many requests, please try again later",
  "details": {
    "retryAfter": 300
  }
}
```

**Headers**:
```
Retry-After: 300
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705315200
```

---

## Security Considerations

### HTTPS

Always use HTTPS in production to protect sensitive data in transit.

### Token Storage

- Store access tokens in memory (not localStorage)
- Store refresh tokens in httpOnly cookies or secure storage
- Never expose tokens in URLs or logs

### CORS

Configure CORS appropriately for your application:

```javascript
// Example CORS configuration
{
  origin: 'https://your-app.com',
  credentials: true
}
```

### Input Validation

All inputs are validated server-side. Client-side validation is recommended but not sufficient.

### Password Requirements

Passwords must meet the following requirements:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

---

## OpenAPI Specification

A complete OpenAPI 3.0 specification is available at:

```
docs/openapi.yaml
```

You can use this specification with tools like Swagger UI, Postman, or code generators.

---

## Support

For issues or questions:
- GitHub Issues: [repository-url]/issues
- Documentation: [repository-url]/docs
- Email: support@example.com
