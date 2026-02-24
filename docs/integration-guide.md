# AADE Integration Guide

## Overview

This guide explains how to integrate the Adaptive Risk-Based Authentication & Device Trust Engine (AADE) into your application. AADE provides adaptive risk-based authentication with device trust management, making it easy to add sophisticated security to your application.

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Integration Patterns](#integration-patterns)
- [Common Scenarios](#common-scenarios)
- [Client Libraries](#client-libraries)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### 1. Install and Configure AADE

```bash
# Clone the repository
git clone https://github.com/your-org/aade.git
cd aade

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
npm run migrate

# Start the server
npm start
```

### 2. Test the API

```bash
# Health check
curl http://localhost:3000/health

# Expected response: {"status":"ok"}
```

### 3. Integrate with Your Application

See [Integration Patterns](#integration-patterns) for detailed examples.

---

## Installation

### Prerequisites

- Node.js 18+ or 20+
- PostgreSQL 14+
- Redis 6+
- npm or yarn

### Server Setup

1. **Clone and Install**:
```bash
git clone https://github.com/your-org/aade.git
cd aade
npm install
```

2. **Database Setup**:
```bash
# Create PostgreSQL database
createdb aade_db

# Run migrations
npm run migrate
```

3. **Generate JWT Keys**:
```bash
# Generate RSA key pair for JWT signing
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

4. **Configure Environment** (see [Configuration](#configuration))

5. **Start Server**:
```bash
# Development
npm run dev

# Production
npm run build
npm start
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Server Configuration
NODE_ENV=production
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
REDIS_PASSWORD=your_redis_password

# JWT Configuration
JWT_ACCESS_SECRET=your_jwt_access_secret_here
JWT_REFRESH_SECRET=your_jwt_refresh_secret_here
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# Security Configuration
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# External Services (optional)
EMAIL_SERVICE_URL=https://api.sendgrid.com/v3
SMS_SERVICE_URL=https://api.twilio.com/2010-04-01
IP_REPUTATION_API_KEY=your_ip_reputation_key
GEOLOCATION_API_KEY=your_geolocation_key

# Logging
LOG_LEVEL=info
LOG_FILE_PATH=./logs/app.log
```

### Configuration Options

#### Server Configuration

- **NODE_ENV**: Environment mode (`development`, `production`, `test`)
- **PORT**: Server port (default: 3000)

#### Database Configuration

- **DB_HOST**: PostgreSQL host
- **DB_PORT**: PostgreSQL port (default: 5432)
- **DB_NAME**: Database name
- **DB_USER**: Database user
- **DB_PASSWORD**: Database password

#### Redis Configuration

- **REDIS_HOST**: Redis host
- **REDIS_PORT**: Redis port (default: 6379)
- **REDIS_PASSWORD**: Redis password (optional)

#### JWT Configuration

- **JWT_ACCESS_SECRET**: Secret for signing access tokens (use strong random string)
- **JWT_REFRESH_SECRET**: Secret for signing refresh tokens (use different strong random string)
- **JWT_ACCESS_EXPIRY**: Access token expiry (e.g., `15m`, `1h`)
- **JWT_REFRESH_EXPIRY**: Refresh token expiry (e.g., `7d`, `30d`)

#### Security Configuration

- **BCRYPT_ROUNDS**: Argon2 cost parameter (default: 12, higher = more secure but slower)
- **RATE_LIMIT_WINDOW_MS**: Rate limit window in milliseconds (default: 900000 = 15 minutes)
- **RATE_LIMIT_MAX_REQUESTS**: Maximum requests per window (default: 100)

#### External Services

- **EMAIL_SERVICE_URL**: Email service API endpoint (for OTP delivery)
- **SMS_SERVICE_URL**: SMS service API endpoint (for OTP delivery)
- **IP_REPUTATION_API_KEY**: API key for IP reputation service
- **GEOLOCATION_API_KEY**: API key for geolocation service

#### Logging

- **LOG_LEVEL**: Logging level (`error`, `warn`, `info`, `debug`)
- **LOG_FILE_PATH**: Path to log file

---

## Integration Patterns

### Pattern 1: Web Application (SPA)

For single-page applications (React, Vue, Angular):

#### Client-Side Implementation

```javascript
// auth.js - Authentication service

class AuthService {
  constructor(apiBaseUrl) {
    this.apiBaseUrl = apiBaseUrl;
    this.accessToken = null;
    this.refreshToken = null;
  }

  // Get device information
  getDeviceInfo() {
    return {
      userAgent: navigator.userAgent,
      screenResolution: `${screen.width}x${screen.height}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language
    };
  }

  // Login
  async login(email, password) {
    const response = await fetch(`${this.apiBaseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password,
        deviceInfo: this.getDeviceInfo()
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message);
    }

    const data = await response.json();

    if (data.requiresMFA) {
      return { requiresMFA: true, userId: data.userId };
    }

    // Store tokens securely
    this.accessToken = data.accessToken;
    this.refreshToken = data.refreshToken;
    
    // Store refresh token in httpOnly cookie (recommended)
    // or secure storage
    localStorage.setItem('refreshToken', data.refreshToken);

    return { success: true, trustLevel: data.trustLevel };
  }

  // Verify MFA
  async verifyMFA(userId, mfaCode) {
    const response = await fetch(`${this.apiBaseUrl}/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId,
        mfaCode,
        deviceInfo: this.getDeviceInfo()
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message);
    }

    const data = await response.json();
    this.accessToken = data.accessToken;
    this.refreshToken = data.refreshToken;
    localStorage.setItem('refreshToken', data.refreshToken);

    return { success: true, trustLevel: data.trustLevel };
  }

  // Refresh token
  async refreshAccessToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await fetch(`${this.apiBaseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });

    if (!response.ok) {
      // Refresh token invalid, redirect to login
      this.logout();
      throw new Error('Session expired');
    }

    const data = await response.json();
    this.accessToken = data.accessToken;
    this.refreshToken = data.refreshToken;
    localStorage.setItem('refreshToken', data.refreshToken);

    return data.accessToken;
  }

  // Make authenticated request
  async authenticatedFetch(url, options = {}) {
    // Add authorization header
    options.headers = {
      ...options.headers,
      'Authorization': `Bearer ${this.accessToken}`
    };

    let response = await fetch(url, options);

    // If token expired, refresh and retry
    if (response.status === 401) {
      const error = await response.json();
      if (error.error === 'token_expired') {
        await this.refreshAccessToken();
        options.headers['Authorization'] = `Bearer ${this.accessToken}`;
        response = await fetch(url, options);
      }
    }

    return response;
  }

  // Logout
  async logout(sessionId) {
    if (this.accessToken) {
      await this.authenticatedFetch(`${this.apiBaseUrl}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId })
      });
    }

    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('refreshToken');
  }

  // Check if authenticated
  isAuthenticated() {
    return this.accessToken !== null;
  }
}

// Usage
const authService = new AuthService('http://localhost:3000');

// Login
try {
  const result = await authService.login('user@example.com', 'password123');
  
  if (result.requiresMFA) {
    // Show MFA input
    const mfaCode = prompt('Enter MFA code:');
    await authService.verifyMFA(result.userId, mfaCode);
  }
  
  console.log('Logged in successfully');
} catch (error) {
  console.error('Login failed:', error.message);
}

// Make authenticated request
const response = await authService.authenticatedFetch('http://localhost:3000/devices');
const devices = await response.json();
```

#### React Example

```jsx
// AuthContext.js
import React, { createContext, useContext, useState, useEffect } from 'react';
import AuthService from './auth';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [authService] = useState(() => new AuthService('http://localhost:3000'));
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already authenticated
    const refreshToken = localStorage.getItem('refreshToken');
    if (refreshToken) {
      authService.refreshAccessToken()
        .then(() => setUser({ authenticated: true }))
        .catch(() => setUser(null))
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [authService]);

  const login = async (email, password) => {
    const result = await authService.login(email, password);
    if (!result.requiresMFA) {
      setUser({ authenticated: true, trustLevel: result.trustLevel });
    }
    return result;
  };

  const logout = async (sessionId) => {
    await authService.logout(sessionId);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ authService, user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}

// LoginPage.jsx
import React, { useState } from 'react';
import { useAuth } from './AuthContext';

function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [userId, setUserId] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');

    try {
      const result = await login(email, password);
      
      if (result.requiresMFA) {
        setMfaRequired(true);
        setUserId(result.userId);
      } else {
        // Redirect to dashboard
        window.location.href = '/dashboard';
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const handleMFAVerify = async (e) => {
    e.preventDefault();
    setError('');

    try {
      await authService.verifyMFA(userId, mfaCode);
      window.location.href = '/dashboard';
    } catch (err) {
      setError(err.message);
    }
  };

  if (mfaRequired) {
    return (
      <form onSubmit={handleMFAVerify}>
        <h2>Enter MFA Code</h2>
        {error && <div className="error">{error}</div>}
        <input
          type="text"
          value={mfaCode}
          onChange={(e) => setMfaCode(e.target.value)}
          placeholder="123456"
          maxLength="6"
        />
        <button type="submit">Verify</button>
      </form>
    );
  }

  return (
    <form onSubmit={handleLogin}>
      <h2>Login</h2>
      {error && <div className="error">{error}</div>}
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      <button type="submit">Login</button>
    </form>
  );
}
```

---

### Pattern 2: Mobile Application

For mobile applications (React Native, Flutter, native iOS/Android):

#### React Native Example

```javascript
// authService.js
import AsyncStorage from '@react-native-async-storage/async-storage';
import DeviceInfo from 'react-native-device-info';

class MobileAuthService {
  constructor(apiBaseUrl) {
    this.apiBaseUrl = apiBaseUrl;
  }

  async getDeviceInfo() {
    return {
      userAgent: await DeviceInfo.getUserAgent(),
      screenResolution: `${DeviceInfo.getDeviceWidth()}x${DeviceInfo.getDeviceHeight()}`,
      timezone: DeviceInfo.getTimezone(),
      language: DeviceInfo.getDeviceLocale()
    };
  }

  async login(email, password) {
    const deviceInfo = await this.getDeviceInfo();
    
    const response = await fetch(`${this.apiBaseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, deviceInfo })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message);
    }

    const data = await response.json();

    if (!data.requiresMFA) {
      // Store tokens securely
      await AsyncStorage.setItem('accessToken', data.accessToken);
      await AsyncStorage.setItem('refreshToken', data.refreshToken);
    }

    return data;
  }

  async getAccessToken() {
    return await AsyncStorage.getItem('accessToken');
  }

  async refreshAccessToken() {
    const refreshToken = await AsyncStorage.getItem('refreshToken');
    
    if (!refreshToken) {
      throw new Error('No refresh token');
    }

    const response = await fetch(`${this.apiBaseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });

    if (!response.ok) {
      await this.logout();
      throw new Error('Session expired');
    }

    const data = await response.json();
    await AsyncStorage.setItem('accessToken', data.accessToken);
    await AsyncStorage.setItem('refreshToken', data.refreshToken);

    return data.accessToken;
  }

  async authenticatedFetch(url, options = {}) {
    let accessToken = await this.getAccessToken();
    
    options.headers = {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`
    };

    let response = await fetch(url, options);

    if (response.status === 401) {
      const error = await response.json();
      if (error.error === 'token_expired') {
        accessToken = await this.refreshAccessToken();
        options.headers['Authorization'] = `Bearer ${accessToken}`;
        response = await fetch(url, options);
      }
    }

    return response;
  }

  async logout() {
    await AsyncStorage.removeItem('accessToken');
    await AsyncStorage.removeItem('refreshToken');
  }
}

export default new MobileAuthService('http://localhost:3000');
```

---

### Pattern 3: Backend-to-Backend Integration

For server-side applications that need to authenticate users:

#### Node.js Example

```javascript
// server.js
const express = require('express');
const axios = require('axios');

const app = express();
const AADE_BASE_URL = 'http://localhost:3000';

// Middleware to verify AADE tokens
async function verifyAADEToken(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);

  try {
    // Verify token by making a request to AADE
    const response = await axios.get(`${AADE_BASE_URL}/sessions`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    // Token is valid, attach user info to request
    req.user = response.data;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Protected route
app.get('/api/protected', verifyAADEToken, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});

// Proxy authentication to AADE
app.post('/api/login', async (req, res) => {
  try {
    const response = await axios.post(`${AADE_BASE_URL}/auth/login`, req.body);
    res.json(response.data);
  } catch (error) {
    res.status(error.response?.status || 500).json(error.response?.data);
  }
});

app.listen(4000, () => {
  console.log('Server running on port 4000');
});
```

---

## Common Scenarios

### Scenario 1: Basic Login Flow

```javascript
// 1. User enters credentials
const email = 'user@example.com';
const password = 'SecurePassword123!';

// 2. Get device information
const deviceInfo = {
  userAgent: navigator.userAgent,
  screenResolution: `${screen.width}x${screen.height}`,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  language: navigator.language
};

// 3. Call login endpoint
const response = await fetch('http://localhost:3000/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password, deviceInfo })
});

const data = await response.json();

// 4. Handle response
if (data.requiresMFA) {
  // Show MFA input
  showMFAInput(data.userId);
} else {
  // Store tokens and redirect
  storeTokens(data.accessToken, data.refreshToken);
  redirectToDashboard();
}
```

### Scenario 2: Step-Up Authentication

```javascript
// User tries to access sensitive operation
async function performSensitiveOperation() {
  const response = await authenticatedFetch('/api/sensitive-operation');
  
  if (response.status === 403) {
    const error = await response.json();
    
    if (error.error === 'insufficient_trust') {
      // Initiate step-up authentication
      const stepUpResponse = await authenticatedFetch('/auth/step-up/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'EMAIL_OTP' })
      });
      
      const { challengeId } = await stepUpResponse.json();
      
      // Show OTP input to user
      const otp = await showOTPInput();
      
      // Verify OTP
      const verifyResponse = await fetch('/auth/step-up/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId, otp })
      });
      
      if (verifyResponse.ok) {
        // Retry sensitive operation
        return await performSensitiveOperation();
      }
    }
  }
  
  return response;
}
```

### Scenario 3: Device Management

```javascript
// List user's devices
async function listDevices() {
  const response = await authenticatedFetch('/devices');
  const { devices } = await response.json();
  
  return devices;
}

// Trust a device
async function trustDevice(deviceId) {
  const response = await authenticatedFetch(`/devices/${deviceId}/trust`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ trustStatus: 'TRUSTED' })
  });
  
  return await response.json();
}

// Revoke a device
async function revokeDevice(deviceId) {
  const response = await authenticatedFetch(`/devices/${deviceId}`, {
    method: 'DELETE'
  });
  
  return await response.json();
}
```

### Scenario 4: Session Management

```javascript
// List active sessions
async function listSessions() {
  const response = await authenticatedFetch('/sessions');
  const { sessions } = await response.json();
  
  return sessions;
}

// Terminate a session
async function terminateSession(sessionId) {
  const response = await authenticatedFetch(`/sessions/${sessionId}`, {
    method: 'DELETE'
  });
  
  return await response.json();
}

// Terminate all other sessions
async function terminateOtherSessions(currentSessionId) {
  const sessions = await listSessions();
  
  for (const session of sessions) {
    if (session.id !== currentSessionId) {
      await terminateSession(session.id);
    }
  }
}
```

---

## Client Libraries

### JavaScript/TypeScript SDK

```bash
npm install @aade/client
```

```javascript
import { AADEClient } from '@aade/client';

const client = new AADEClient({
  baseUrl: 'http://localhost:3000',
  autoRefresh: true
});

// Login
const result = await client.auth.login({
  email: 'user@example.com',
  password: 'password123'
});

// Make authenticated requests
const devices = await client.devices.list();
```

### Python SDK

```bash
pip install aade-client
```

```python
from aade_client import AADEClient

client = AADEClient(base_url='http://localhost:3000')

# Login
result = client.auth.login(
    email='user@example.com',
    password='password123',
    device_info=client.get_device_info()
)

# Make authenticated requests
devices = client.devices.list()
```

---

## Best Practices

### Security

1. **Always use HTTPS in production**
2. **Store tokens securely**:
   - Web: Use httpOnly cookies for refresh tokens
   - Mobile: Use secure storage (Keychain/Keystore)
   - Never store tokens in localStorage for sensitive applications
3. **Implement token refresh logic** to handle expired tokens gracefully
4. **Validate all inputs** on the client side before sending to API
5. **Handle rate limiting** by implementing exponential backoff

### Performance

1. **Cache device information** to avoid recalculating on every request
2. **Implement request queuing** during token refresh to avoid multiple refresh requests
3. **Use connection pooling** for backend integrations
4. **Monitor API response times** and implement timeouts

### User Experience

1. **Show clear error messages** for authentication failures
2. **Implement loading states** during authentication
3. **Provide feedback** for step-up authentication requirements
4. **Allow users to manage** their devices and sessions
5. **Implement "Remember Me"** functionality using refresh tokens

### Error Handling

```javascript
async function handleAuthError(error) {
  switch (error.error) {
    case 'invalid_credentials':
      showError('Invalid email or password');
      break;
    case 'account_locked':
      showError(`Account locked until ${error.details.lockoutUntil}`);
      break;
    case 'rate_limit_exceeded':
      showError(`Too many attempts. Try again in ${error.details.retryAfter} seconds`);
      break;
    case 'insufficient_trust':
      initiateStepUpAuth();
      break;
    default:
      showError('An error occurred. Please try again.');
  }
}
```

---

## Troubleshooting

### Common Issues

#### Issue: "Invalid token" errors

**Solution**: Implement automatic token refresh:

```javascript
async function authenticatedFetch(url, options = {}) {
  let response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`
    }
  });

  if (response.status === 401) {
    const error = await response.json();
    if (error.error === 'token_expired') {
      await refreshAccessToken();
      response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${accessToken}`
        }
      });
    }
  }

  return response;
}
```

#### Issue: Rate limiting

**Solution**: Implement exponential backoff:

```javascript
async function fetchWithRetry(url, options, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    const response = await fetch(url, options);
    
    if (response.status !== 429) {
      return response;
    }
    
    const retryAfter = response.headers.get('Retry-After') || Math.pow(2, i);
    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
  }
  
  throw new Error('Max retries exceeded');
}
```

#### Issue: CORS errors

**Solution**: Configure CORS in AADE:

```javascript
// In AADE server configuration
app.use(cors({
  origin: 'https://your-app.com',
  credentials: true
}));
```

#### Issue: Device not recognized

**Solution**: Ensure device information is consistent:

```javascript
// Store device info in session storage
const deviceInfo = sessionStorage.getItem('deviceInfo') || JSON.stringify({
  userAgent: navigator.userAgent,
  screenResolution: `${screen.width}x${screen.height}`,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  language: navigator.language
});

sessionStorage.setItem('deviceInfo', deviceInfo);
```

### Debug Mode

Enable debug logging:

```javascript
const client = new AADEClient({
  baseUrl: 'http://localhost:3000',
  debug: true
});
```

### Support

For additional help:
- Check the [API Reference](./api-reference.md)
- Review [example applications](../examples/)
- Open an issue on GitHub
- Contact support@example.com

---

## Next Steps

- Review the [API Reference](./api-reference.md) for detailed endpoint documentation
- Check the [Deployment Guide](./deployment-guide.md) for production deployment
- Explore [example applications](../examples/) for complete implementations
