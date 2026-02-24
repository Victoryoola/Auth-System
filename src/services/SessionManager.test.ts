import { SessionManager } from './SessionManager';
import { SessionTrustLevel } from '../types/enums';
import { pool } from '../config/database';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

// Generate RSA key pair for testing
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Mock Redis client
class MockRedisClient {
  private store: Map<string, { value: string; expiry: number }> = new Map();

  async get(key: string): Promise<string | null> {
    const item = this.store.get(key);
    if (!item) return null;
    if (Date.now() > item.expiry) {
      this.store.delete(key);
      return null;
    }
    return item.value;
  }

  async setEx(key: string, seconds: number, value: string): Promise<void> {
    this.store.set(key, {
      value,
      expiry: Date.now() + seconds * 1000,
    });
  }

  async del(key: string): Promise<void> {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

describe('SessionManager', () => {
  let sessionManager: SessionManager;
  let mockRedis: MockRedisClient;
  const testUserId = 'test-user-123';
  const testDeviceIdentity = 'device-abc-123';
  const testIpAddress = '192.168.1.1';

  beforeAll(async () => {
    // Ensure database connection
    await pool.query('SELECT 1');
  });

  beforeEach(async () => {
    mockRedis = new MockRedisClient();
    sessionManager = new SessionManager(privateKey, publicKey, mockRedis as any);

    // Clean up test data
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [testUserId]);
  });

  afterEach(async () => {
    mockRedis.clear();
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [testUserId]);
  });

  afterAll(async () => {
    await pool.end();
  });

  describe('createSession', () => {
    it('should create a session with valid tokens', async () => {
      const result = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      expect(result.id).toBeDefined();
      expect(result.userId).toBe(testUserId);
      expect(result.trustLevel).toBe(SessionTrustLevel.FULL_TRUST);
      expect(result.deviceIdentity).toBe(testDeviceIdentity);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(result.revoked).toBe(false);
    });

    it('should generate cryptographically secure tokens', async () => {
      const session1 = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      const session2 = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      // Tokens should be different
      expect(session1.accessToken).not.toBe(session2.accessToken);
      expect(session1.refreshToken).not.toBe(session2.refreshToken);

      // Tokens should have sufficient length (indicating entropy)
      expect(session1.refreshToken.length).toBeGreaterThan(64);
      expect(session2.refreshToken.length).toBeGreaterThan(64);
    });

    it('should create session with correct trust level', async () => {
      const levels = [
        SessionTrustLevel.FULL_TRUST,
        SessionTrustLevel.LIMITED_TRUST,
        SessionTrustLevel.UNVERIFIED,
        SessionTrustLevel.HIGH_RISK,
      ];

      for (const level of levels) {
        const result = await sessionManager.createSession(
          testUserId,
          level,
          testDeviceIdentity,
          testIpAddress
        );

        expect(result.trustLevel).toBe(level);
      }
    });
  });

  describe('validateToken', () => {
    it('should validate a valid token', async () => {
      const session = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      const validation = await sessionManager.validateToken(session.accessToken);

      expect(validation.valid).toBe(true);
      expect(validation.session).toBeDefined();
      expect(validation.session?.userId).toBe(testUserId);
    });

    it('should reject token with invalid signature', async () => {
      const fakeToken = jwt.sign(
        { sessionId: 'fake', userId: testUserId },
        'wrong-key',
        { algorithm: 'HS256' }
      );

      const validation = await sessionManager.validateToken(fakeToken);

      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('Invalid token signature');
    });

    it('should reject expired token', async () => {
      // Create a token that expires immediately
      const sessionId = crypto.randomUUID();
      const expiredToken = jwt.sign(
        {
          sessionId,
          userId: testUserId,
          trustLevel: SessionTrustLevel.FULL_TRUST,
          deviceIdentity: testDeviceIdentity,
          jti: crypto.randomBytes(32).toString('hex'),
        },
        privateKey,
        { algorithm: 'RS256', expiresIn: '0s' }
      );

      // Wait a moment to ensure expiration
      await new Promise((resolve) => setTimeout(resolve, 100));

      const validation = await sessionManager.validateToken(expiredToken);

      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('Token expired');
    });

    it('should detect token replay attack', async () => {
      const session = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      // First use should succeed
      const validation1 = await sessionManager.validateToken(session.accessToken);
      expect(validation1.valid).toBe(true);

      // Second use should be detected as replay
      const validation2 = await sessionManager.validateToken(session.accessToken);
      expect(validation2.valid).toBe(false);
      expect(validation2.reason).toBe('Token replay detected');
    });

    it('should reject token for revoked session', async () => {
      const session = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      // Revoke the session
      await sessionManager.revokeSession(session.id);

      const validation = await sessionManager.validateToken(session.accessToken);

      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('Session not found or revoked');
    });
  });

  describe('refreshSession', () => {
    it('should refresh tokens successfully', async () => {
      const session = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      const refreshResult = await sessionManager.refreshSession(session.refreshToken);

      expect(refreshResult.accessToken).toBeDefined();
      expect(refreshResult.refreshToken).toBeDefined();
      expect(refreshResult.expiresIn).toBeGreaterThan(0);

      // New tokens should be different from old tokens
      expect(refreshResult.accessToken).not.toBe(session.accessToken);
      expect(refreshResult.refreshToken).not.toBe(session.refreshToken);
    });

    it('should rotate refresh token on use', async () => {
      const session = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      const refresh1 = await sessionManager.refreshSession(session.refreshToken);
      const refresh2 = await sessionManager.refreshSession(refresh1.refreshToken);

      // Each refresh should produce a new refresh token
      expect(refresh1.refreshToken).not.toBe(session.refreshToken);
      expect(refresh2.refreshToken).not.toBe(refresh1.refreshToken);
    });

    it('should reject reused refresh token (replay attack)', async () => {
      const session = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      // Use refresh token once
      await sessionManager.refreshSession(session.refreshToken);

      // Try to reuse the same refresh token
      await expect(sessionManager.refreshSession(session.refreshToken)).rejects.toThrow(
        'Invalid refresh token - potential replay attack detected'
      );
    });

    it('should reject invalid refresh token', async () => {
      const fakeRefreshToken = crypto.randomBytes(64).toString('hex');

      await expect(sessionManager.refreshSession(fakeRefreshToken)).rejects.toThrow();
    });
  });

  describe('promoteTrustLevel', () => {
    it('should promote session trust level', async () => {
      const session = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.UNVERIFIED,
        testDeviceIdentity,
        testIpAddress
      );

      await sessionManager.promoteTrustLevel(session.id, SessionTrustLevel.FULL_TRUST);

      const sessions = await sessionManager.getActiveSessions(testUserId);
      const updatedSession = sessions.find((s) => s.id === session.id);

      expect(updatedSession?.trustLevel).toBe(SessionTrustLevel.FULL_TRUST);
    });

    it('should update trust level without requiring re-authentication', async () => {
      const session = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.LIMITED_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      const originalAccessToken = session.accessToken;

      await sessionManager.promoteTrustLevel(session.id, SessionTrustLevel.FULL_TRUST);

      // Original token should still be valid (no re-auth required)
      const validation = await sessionManager.validateToken(originalAccessToken);
      expect(validation.valid).toBe(true);
    });
  });

  describe('getActiveSessions', () => {
    it('should return all active sessions for a user', async () => {
      await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.LIMITED_TRUST,
        'device-xyz-456',
        testIpAddress
      );

      const sessions = await sessionManager.getActiveSessions(testUserId);

      expect(sessions.length).toBe(2);
      expect(sessions.every((s) => s.userId === testUserId)).toBe(true);
      expect(sessions.every((s) => !s.revoked)).toBe(true);
    });

    it('should not return revoked sessions', async () => {
      const session1 = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.LIMITED_TRUST,
        'device-xyz-456',
        testIpAddress
      );

      // Revoke one session
      await sessionManager.revokeSession(session1.id);

      const sessions = await sessionManager.getActiveSessions(testUserId);

      expect(sessions.length).toBe(1);
      expect(sessions[0].id).not.toBe(session1.id);
    });

    it('should return empty array for user with no sessions', async () => {
      const sessions = await sessionManager.getActiveSessions('non-existent-user');

      expect(sessions).toEqual([]);
    });
  });

  describe('revokeSession', () => {
    it('should revoke a specific session', async () => {
      const session = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      await sessionManager.revokeSession(session.id);

      const validation = await sessionManager.validateToken(session.accessToken);

      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('Session not found or revoked');
    });

    it('should only revoke specified session, not others', async () => {
      const session1 = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      const session2 = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.LIMITED_TRUST,
        'device-xyz-456',
        testIpAddress
      );

      await sessionManager.revokeSession(session1.id);

      const validation1 = await sessionManager.validateToken(session1.accessToken);
      const validation2 = await sessionManager.validateToken(session2.accessToken);

      expect(validation1.valid).toBe(false);
      expect(validation2.valid).toBe(true);
    });
  });

  describe('revokeDeviceSessions', () => {
    it('should revoke all sessions for a device', async () => {
      const session1 = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      const session2 = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.LIMITED_TRUST,
        testDeviceIdentity,
        testIpAddress
      );

      const session3 = await sessionManager.createSession(
        testUserId,
        SessionTrustLevel.FULL_TRUST,
        'different-device',
        testIpAddress
      );

      await sessionManager.revokeDeviceSessions(testDeviceIdentity);

      const validation1 = await sessionManager.validateToken(session1.accessToken);
      const validation2 = await sessionManager.validateToken(session2.accessToken);
      const validation3 = await sessionManager.validateToken(session3.accessToken);

      expect(validation1.valid).toBe(false);
      expect(validation2.valid).toBe(false);
      expect(validation3.valid).toBe(true); // Different device should remain valid
    });
  });
});
