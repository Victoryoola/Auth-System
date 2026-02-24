import { AuthService, Credentials } from './AuthService';
import { DeviceRegistry } from './DeviceRegistry';
import { RiskEngine } from './RiskEngine';
import { SessionManager } from './SessionManager';
import { DeviceInfo } from '../types/device';
import { SessionTrustLevel } from '../types/enums';
import { pool } from '../config/database';
import argon2 from 'argon2';
import speakeasy from 'speakeasy';

// Mock dependencies
jest.mock('../config/database');
jest.mock('./DeviceRegistry');
jest.mock('./RiskEngine');
jest.mock('./SessionManager');

describe('AuthService', () => {
  let authService: AuthService;
  let mockDeviceRegistry: jest.Mocked<DeviceRegistry>;
  let mockRiskEngine: jest.Mocked<RiskEngine>;
  let mockSessionManager: jest.Mocked<SessionManager>;
  let mockPool: any;

  const mockDeviceInfo: DeviceInfo = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
    ipAddress: '192.168.1.1',
    screenResolution: '1920x1080',
    timezone: 'America/New_York',
    language: 'en-US',
  };

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Setup mock pool
    mockPool = {
      query: jest.fn(),
      connect: jest.fn(),
    };
    (pool as any).query = mockPool.query;

    // Create mock instances
    mockDeviceRegistry = new DeviceRegistry() as jest.Mocked<DeviceRegistry>;
    mockRiskEngine = new RiskEngine(mockDeviceRegistry) as jest.Mocked<RiskEngine>;
    mockSessionManager = new SessionManager('private', 'public') as jest.Mocked<SessionManager>;

    // Create auth service
    authService = new AuthService(
      mockDeviceRegistry,
      mockRiskEngine,
      mockSessionManager
    );
  });

  describe('Password Hashing and Validation', () => {
    describe('hashPassword', () => {
      it('should hash password using Argon2id', async () => {
        const password = 'SecurePassword123!';
        const hash = await authService.hashPassword(password);

        expect(hash).toBeDefined();
        expect(hash).not.toBe(password);
        expect(hash.startsWith('$argon2id$')).toBe(true);
      });

      it('should produce different hashes for same password', async () => {
        const password = 'SecurePassword123!';
        const hash1 = await authService.hashPassword(password);
        const hash2 = await authService.hashPassword(password);

        expect(hash1).not.toBe(hash2);
      });

      it('should handle empty password', async () => {
        const password = '';
        const hash = await authService.hashPassword(password);

        expect(hash).toBeDefined();
        expect(hash.startsWith('$argon2id$')).toBe(true);
      });
    });

    describe('verifyPassword', () => {
      it('should verify correct password', async () => {
        const password = 'SecurePassword123!';
        const hash = await authService.hashPassword(password);

        const isValid = await authService.verifyPassword(password, hash);
        expect(isValid).toBe(true);
      });

      it('should reject incorrect password', async () => {
        const password = 'SecurePassword123!';
        const wrongPassword = 'WrongPassword456!';
        const hash = await authService.hashPassword(password);

        const isValid = await authService.verifyPassword(wrongPassword, hash);
        expect(isValid).toBe(false);
      });

      it('should use constant-time comparison', async () => {
        const password = 'SecurePassword123!';
        const hash = await authService.hashPassword(password);

        // Measure time for correct password
        const start1 = Date.now();
        await authService.verifyPassword(password, hash);
        const time1 = Date.now() - start1;

        // Measure time for incorrect password
        const start2 = Date.now();
        await authService.verifyPassword('WrongPassword', hash);
        const time2 = Date.now() - start2;

        // Times should be similar (within reasonable margin)
        // Note: This is a basic check; true constant-time is handled by argon2
        expect(Math.abs(time1 - time2)).toBeLessThan(100);
      });

      it('should handle invalid hash format', async () => {
        const password = 'SecurePassword123!';
        const invalidHash = 'not-a-valid-hash';

        const isValid = await authService.verifyPassword(password, invalidHash);
        expect(isValid).toBe(false);
      });
    });
  });

  describe('Authentication Flow', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      password_hash: '$argon2id$v=19$m=65536,t=3,p=4$hash',
      mfa_enabled: false,
      mfa_secret: null,
      created_at: new Date(),
      updated_at: new Date(),
      last_login_at: null,
      failed_login_attempts: 0,
      last_failed_login_at: null,
      account_locked: false,
      lockout_until: null,
    };

    describe('authenticate', () => {
      it('should authenticate user with valid credentials', async () => {
        const credentials: Credentials = {
          email: 'test@example.com',
          password: 'SecurePassword123!',
        };

        // Hash the password for comparison
        const passwordHash = await argon2.hash(credentials.password);
        mockUser.password_hash = passwordHash;

        // Mock database query
        mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });
        mockPool.query.mockResolvedValueOnce({ rows: [] }); // Reset failed attempts
        mockPool.query.mockResolvedValueOnce({ rows: [] }); // Update last login

        // Mock device registry
        mockDeviceRegistry.generateIdentity.mockReturnValue('device-123');
        mockDeviceRegistry.registerDevice.mockResolvedValue({} as any);

        // Mock risk engine
        mockRiskEngine.calculateRiskScore.mockResolvedValue({
          score: 10,
          factors: [],
          trustLevel: SessionTrustLevel.FULL_TRUST,
        });

        // Mock session manager
        mockSessionManager.createSession.mockResolvedValue({
          id: 'session-123',
          userId: 'user-123',
          trustLevel: SessionTrustLevel.FULL_TRUST,
          deviceIdentity: 'device-123',
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
          accessTokenHash: 'hash',
          refreshTokenHash: 'hash',
          refreshTokenFamily: 'family',
          accessTokenExpiry: new Date(),
          refreshTokenExpiry: new Date(),
          createdAt: new Date(),
          lastActivity: new Date(),
          ipAddress: '192.168.1.1',
          revoked: false,
        });

        const result = await authService.authenticate(credentials, mockDeviceInfo);

        expect(result.accessToken).toBe('access-token');
        expect(result.refreshToken).toBe('refresh-token');
        expect(result.trustLevel).toBe(SessionTrustLevel.FULL_TRUST);
        expect(result.requiresMFA).toBe(false);
        expect(mockDeviceRegistry.generateIdentity).toHaveBeenCalledWith(mockDeviceInfo);
        expect(mockRiskEngine.calculateRiskScore).toHaveBeenCalled();
        expect(mockSessionManager.createSession).toHaveBeenCalled();
      });

      it('should reject invalid credentials', async () => {
        const credentials: Credentials = {
          email: 'test@example.com',
          password: 'WrongPassword',
        };

        // Mock database query
        mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });
        mockPool.query.mockResolvedValueOnce({ rows: [{ failed_login_attempts: 1 }] });

        await expect(
          authService.authenticate(credentials, mockDeviceInfo)
        ).rejects.toThrow('Invalid credentials');
      });

      it('should require MFA when enabled', async () => {
        const credentials: Credentials = {
          email: 'test@example.com',
          password: 'SecurePassword123!',
        };

        const passwordHash = await argon2.hash(credentials.password);
        const mfaUser = { ...mockUser, password_hash: passwordHash, mfa_enabled: true };

        mockPool.query.mockResolvedValueOnce({ rows: [mfaUser] });
        mockPool.query.mockResolvedValueOnce({ rows: [] }); // Reset failed attempts

        const result = await authService.authenticate(credentials, mockDeviceInfo);

        expect(result.requiresMFA).toBe(true);
        expect(result.accessToken).toBe('');
        expect(result.userId).toBe('user-123');
      });

      it('should reject authentication for locked account', async () => {
        const credentials: Credentials = {
          email: 'test@example.com',
          password: 'SecurePassword123!',
        };

        const lockedUser = {
          ...mockUser,
          account_locked: true,
          lockout_until: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes from now
        };

        mockPool.query.mockResolvedValueOnce({ rows: [lockedUser] });

        await expect(
          authService.authenticate(credentials, mockDeviceInfo)
        ).rejects.toThrow('Account locked');
      });

      it('should increment failed attempts on wrong password', async () => {
        const credentials: Credentials = {
          email: 'test@example.com',
          password: 'WrongPassword',
        };

        mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });
        mockPool.query.mockResolvedValueOnce({ rows: [{ failed_login_attempts: 1 }] });

        await expect(
          authService.authenticate(credentials, mockDeviceInfo)
        ).rejects.toThrow('Invalid credentials');

        expect(mockPool.query).toHaveBeenCalledWith(
          expect.stringContaining('failed_login_attempts = failed_login_attempts + 1'),
          expect.any(Array)
        );
      });

      it('should reject authentication for non-existent user', async () => {
        const credentials: Credentials = {
          email: 'nonexistent@example.com',
          password: 'Password123!',
        };

        mockPool.query.mockResolvedValueOnce({ rows: [] });

        await expect(
          authService.authenticate(credentials, mockDeviceInfo)
        ).rejects.toThrow('Invalid credentials');
      });
    });

    describe('verifyMFA', () => {
      it('should verify valid TOTP code', async () => {
        const secret = speakeasy.generateSecret({ length: 32 });
        const token = speakeasy.totp({
          secret: secret.base32,
          encoding: 'base32',
        });

        const mfaUser = {
          ...mockUser,
          mfa_enabled: true,
          mfa_secret: secret.base32,
        };

        mockPool.query.mockResolvedValueOnce({ rows: [mfaUser] });
        mockPool.query.mockResolvedValueOnce({ rows: [] }); // Reset failed attempts
        mockPool.query.mockResolvedValueOnce({ rows: [] }); // Update last login

        mockDeviceRegistry.generateIdentity.mockReturnValue('device-123');
        mockDeviceRegistry.registerDevice.mockResolvedValue({} as any);

        mockRiskEngine.calculateRiskScore.mockResolvedValue({
          score: 10,
          factors: [],
          trustLevel: SessionTrustLevel.FULL_TRUST,
        });

        mockSessionManager.createSession.mockResolvedValue({
          id: 'session-123',
          userId: 'user-123',
          trustLevel: SessionTrustLevel.FULL_TRUST,
          deviceIdentity: 'device-123',
          accessToken: 'access-token',
          refreshToken: 'refresh-token',
          accessTokenHash: 'hash',
          refreshTokenHash: 'hash',
          refreshTokenFamily: 'family',
          accessTokenExpiry: new Date(),
          refreshTokenExpiry: new Date(),
          createdAt: new Date(),
          lastActivity: new Date(),
          ipAddress: '192.168.1.1',
          revoked: false,
        });

        const result = await authService.verifyMFA('user-123', token, mockDeviceInfo);

        expect(result.accessToken).toBe('access-token');
        expect(result.requiresMFA).toBe(false);
      });

      it('should reject invalid TOTP code', async () => {
        const secret = speakeasy.generateSecret({ length: 32 });
        const invalidToken = '000000';

        const mfaUser = {
          ...mockUser,
          mfa_enabled: true,
          mfa_secret: secret.base32,
        };

        mockPool.query.mockResolvedValueOnce({ rows: [mfaUser] });
        mockPool.query.mockResolvedValueOnce({ rows: [{ failed_login_attempts: 1 }] });

        await expect(
          authService.verifyMFA('user-123', invalidToken, mockDeviceInfo)
        ).rejects.toThrow('Invalid MFA code');
      });

      it('should reject MFA verification for user without MFA enabled', async () => {
        mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });

        await expect(
          authService.verifyMFA('user-123', '123456', mockDeviceInfo)
        ).rejects.toThrow('MFA not enabled for this user');
      });
    });
  });

  describe('Rate Limiting and Security Controls', () => {
    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      password_hash: '$argon2id$v=19$m=65536,t=3,p=4$hash',
      mfa_enabled: false,
      mfa_secret: null,
      created_at: new Date(),
      updated_at: new Date(),
      last_login_at: null,
      failed_login_attempts: 0,
      last_failed_login_at: null,
      account_locked: false,
      lockout_until: null,
    };

    it('should enforce IP-based rate limiting after max attempts', async () => {
      const credentials: Credentials = {
        email: 'test@example.com',
        password: 'WrongPassword',
      };

      // Create a new AuthService instance to ensure clean state
      const freshAuthService = new AuthService(
        mockDeviceRegistry,
        mockRiskEngine,
        mockSessionManager
      );

      mockPool.query.mockResolvedValue({ rows: [mockUser] });

      // Make more than MAX_FAILED_ATTEMPTS (5) failed attempts
      for (let i = 0; i < 6; i++) {
        mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });
        mockPool.query.mockResolvedValueOnce({ rows: [{ failed_login_attempts: i + 1 }] });

        try {
          await freshAuthService.authenticate(credentials, mockDeviceInfo);
          fail('Should have thrown an error');
        } catch (error: any) {
          // Attempts 1-3: "Invalid credentials"
          // Attempts 4-5: "CAPTCHA verification required"
          // Attempt 6+: "Rate limit exceeded"
          if (i < 3) {
            expect(error.message).toBe('Invalid credentials');
          } else if (i < 5) {
            expect(error.message).toBe('CAPTCHA verification required');
          } else {
            expect(error.message).toBe('Rate limit exceeded. Please try again later.');
          }
        }
      }
    });

    it('should require CAPTCHA after threshold failures', async () => {
      const credentials: Credentials = {
        email: 'test@example.com',
        password: 'WrongPassword',
      };

      mockPool.query.mockResolvedValue({ rows: [mockUser] });

      // Make 3 failed attempts (CAPTCHA threshold)
      for (let i = 0; i < 3; i++) {
        mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });
        mockPool.query.mockResolvedValueOnce({ rows: [{ failed_login_attempts: i + 1 }] });

        try {
          await authService.authenticate(credentials, mockDeviceInfo);
        } catch (error) {
          // Expected to fail
        }
      }

      // Next attempt should require CAPTCHA
      await expect(
        authService.authenticate(credentials, mockDeviceInfo)
      ).rejects.toThrow('CAPTCHA verification required');
    });

    it('should reset rate limit after successful authentication', async () => {
      const credentials: Credentials = {
        email: 'test@example.com',
        password: 'SecurePassword123!',
      };

      const passwordHash = await argon2.hash(credentials.password);
      mockUser.password_hash = passwordHash;

      // Make a failed attempt first
      mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });
      mockPool.query.mockResolvedValueOnce({ rows: [{ failed_login_attempts: 1 }] });

      try {
        await authService.authenticate(
          { ...credentials, password: 'WrongPassword' },
          mockDeviceInfo
        );
      } catch (error) {
        // Expected to fail
      }

      // Now authenticate successfully
      mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });
      mockPool.query.mockResolvedValueOnce({ rows: [] }); // Reset failed attempts
      mockPool.query.mockResolvedValueOnce({ rows: [] }); // Update last login

      mockDeviceRegistry.generateIdentity.mockReturnValue('device-123');
      mockDeviceRegistry.registerDevice.mockResolvedValue({} as any);

      mockRiskEngine.calculateRiskScore.mockResolvedValue({
        score: 10,
        factors: [],
        trustLevel: SessionTrustLevel.FULL_TRUST,
      });

      mockSessionManager.createSession.mockResolvedValue({
        id: 'session-123',
        userId: 'user-123',
        trustLevel: SessionTrustLevel.FULL_TRUST,
        deviceIdentity: 'device-123',
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        accessTokenHash: 'hash',
        refreshTokenHash: 'hash',
        refreshTokenFamily: 'family',
        accessTokenExpiry: new Date(),
        refreshTokenExpiry: new Date(),
        createdAt: new Date(),
        lastActivity: new Date(),
        ipAddress: '192.168.1.1',
        revoked: false,
      });

      const result = await authService.authenticate(credentials, mockDeviceInfo);
      expect(result.accessToken).toBeDefined();

      // Rate limit should be reset, so another attempt should work
      mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });
      mockPool.query.mockResolvedValueOnce({ rows: [] });
      mockPool.query.mockResolvedValueOnce({ rows: [] });

      const result2 = await authService.authenticate(credentials, mockDeviceInfo);
      expect(result2.accessToken).toBeDefined();
    });

    it('should lock account after 5 failed attempts', async () => {
      const credentials: Credentials = {
        email: 'test@example.com',
        password: 'WrongPassword',
      };

      mockPool.query.mockResolvedValueOnce({ rows: [mockUser] });
      mockPool.query.mockResolvedValueOnce({ rows: [{ failed_login_attempts: 5 }] });
      mockPool.query.mockResolvedValueOnce({ rows: [] }); // Lock account

      await expect(
        authService.authenticate(credentials, mockDeviceInfo)
      ).rejects.toThrow('Invalid credentials');

      // Verify account lock query was called
      expect(mockPool.query).toHaveBeenCalledWith(
        expect.stringContaining('account_locked = true'),
        expect.any(Array)
      );
    });
  });

  describe('logout', () => {
    it('should revoke session on logout', async () => {
      mockSessionManager.revokeSession.mockResolvedValue();

      await authService.logout('session-123');

      expect(mockSessionManager.revokeSession).toHaveBeenCalledWith('session-123');
    });
  });
});
