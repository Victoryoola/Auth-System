import argon2 from 'argon2';
import speakeasy from 'speakeasy';
import { pool } from '../config/database';
import { DeviceRegistry } from './DeviceRegistry';
import { RiskEngine } from './RiskEngine';
import { SessionManager } from './SessionManager';
import { DeviceInfo } from '../types/device';
import { SessionTrustLevel } from '../types/enums';
import { User } from '../models/User';

/**
 * Authentication credentials
 */
export interface Credentials {
  email: string;
  password: string;
}

/**
 * Authentication result
 */
export interface AuthResult {
  accessToken: string;
  refreshToken: string;
  trustLevel: SessionTrustLevel;
  requiresMFA: boolean;
  expiresIn: number;
  userId?: string;
}

/**
 * Rate limit tracking for IP addresses
 */
interface RateLimitEntry {
  attempts: number;
  lastAttempt: Date;
  requiresCaptcha: boolean;
}

/**
 * Auth Service
 * Orchestrates authentication flow with password validation, MFA, risk assessment, and rate limiting
 */
export class AuthService {
  private deviceRegistry: DeviceRegistry;
  private riskEngine: RiskEngine;
  private sessionManager: SessionManager;
  private ipRateLimits: Map<string, RateLimitEntry>;
  private readonly MAX_FAILED_ATTEMPTS = 5;
  private readonly RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
  private readonly CAPTCHA_THRESHOLD = 3;

  constructor(
    deviceRegistry: DeviceRegistry,
    riskEngine: RiskEngine,
    sessionManager: SessionManager
  ) {
    this.deviceRegistry = deviceRegistry;
    this.riskEngine = riskEngine;
    this.sessionManager = sessionManager;
    this.ipRateLimits = new Map();
  }

  /**
   * Hash a password using Argon2id
   * Uses appropriate cost parameters for security
   */
  async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536, // 64 MB
      timeCost: 3,
      parallelism: 4,
    });
  }

  /**
   * Verify a password against a hash using constant-time comparison
   * Argon2 provides built-in constant-time comparison
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      // If verification fails due to invalid hash format, return false
      return false;
    }
  }

  /**
   * Authenticate user with credentials and device information
   */
  async authenticate(
    credentials: Credentials,
    deviceInfo: DeviceInfo
  ): Promise<AuthResult> {
    const { email, password } = credentials;
    const ipAddress = deviceInfo.ipAddress;

    // Check IP-based rate limiting (this may throw)
    const rateLimitStatus = this.checkRateLimit(ipAddress);

    // Get user from database
    const user = await this.getUserByEmail(email);
    
    if (!user) {
      // Increment rate limit for failed attempt
      this.recordFailedAttempt(ipAddress);
      throw new Error('Invalid credentials');
    }

    // Check if account is locked
    if (user.accountLocked && user.lockoutUntil && user.lockoutUntil > new Date()) {
      const lockoutRemaining = Math.ceil(
        (user.lockoutUntil.getTime() - Date.now()) / 1000
      );
      // Still record the attempt even for locked accounts
      this.recordFailedAttempt(ipAddress);
      throw new Error(`Account locked. Try again in ${lockoutRemaining} seconds`);
    }

    // If CAPTCHA is required, throw error but still record the attempt
    if (rateLimitStatus.requiresCaptcha) {
      this.recordFailedAttempt(ipAddress);
      throw new Error('CAPTCHA verification required');
    }

    // Verify password using constant-time comparison
    const isValidPassword = await this.verifyPassword(password, user.passwordHash);

    if (!isValidPassword) {
      // Increment failed login attempts
      await this.incrementFailedAttempts(user.id);
      this.recordFailedAttempt(ipAddress);
      throw new Error('Invalid credentials');
    }

    // Reset failed attempts on successful password validation
    await this.resetFailedAttempts(user.id);
    this.resetRateLimit(ipAddress);

    // Check if MFA is required
    if (user.mfaEnabled) {
      return {
        accessToken: '',
        refreshToken: '',
        trustLevel: SessionTrustLevel.UNVERIFIED,
        requiresMFA: true,
        expiresIn: 0,
        userId: user.id,
      };
    }

    // Generate device identity (may be null if user opted out)
    const deviceIdentity = await this.deviceRegistry.generateIdentity(deviceInfo, user.id);

    // Register or update device (only if tracking is enabled)
    await this.deviceRegistry.registerDevice(user.id, deviceIdentity, {
      deviceType: this.extractDeviceType(deviceInfo.userAgent),
      browser: this.extractBrowser(deviceInfo.userAgent),
      operatingSystem: this.extractOS(deviceInfo.userAgent),
      lastIpAddress: ipAddress,
    });

    // Calculate risk score (use empty string for device identity if opted out)
    const riskScore = await this.riskEngine.calculateRiskScore({
      userId: user.id,
      deviceIdentity: deviceIdentity || '',
      ipAddress,
      timestamp: new Date(),
      failedAttempts: user.failedLoginAttempts,
    });

    // Create session with appropriate trust level
    const session = await this.sessionManager.createSession(
      user.id,
      riskScore.trustLevel,
      deviceIdentity || '',
      ipAddress
    );

    // Update last login timestamp
    await this.updateLastLogin(user.id);

    return {
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      trustLevel: riskScore.trustLevel,
      requiresMFA: false,
      expiresIn: 15 * 60, // 15 minutes
    };
  }

  /**
   * Verify MFA code for a user
   */
  async verifyMFA(
    userId: string,
    mfaCode: string,
    deviceInfo: DeviceInfo
  ): Promise<AuthResult> {
    // Get user from database
    const user = await this.getUserById(userId);

    if (!user) {
      throw new Error('User not found');
    }

    if (!user.mfaEnabled || !user.mfaSecret) {
      throw new Error('MFA not enabled for this user');
    }

    // Verify TOTP code
    const isValid = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: mfaCode,
      window: 1, // Allow 1 time step before/after for clock skew
    });

    if (!isValid) {
      // Increment failed attempts
      await this.incrementFailedAttempts(user.id);
      throw new Error('Invalid MFA code');
    }

    // Reset failed attempts
    await this.resetFailedAttempts(user.id);

    // Generate device identity (may be null if user opted out)
    const deviceIdentity = await this.deviceRegistry.generateIdentity(deviceInfo, user.id);

    // Register or update device (only if tracking is enabled)
    await this.deviceRegistry.registerDevice(user.id, deviceIdentity, {
      deviceType: this.extractDeviceType(deviceInfo.userAgent),
      browser: this.extractBrowser(deviceInfo.userAgent),
      operatingSystem: this.extractOS(deviceInfo.userAgent),
      lastIpAddress: deviceInfo.ipAddress,
    });

    // Calculate risk score (use empty string for device identity if opted out)
    const riskScore = await this.riskEngine.calculateRiskScore({
      userId: user.id,
      deviceIdentity: deviceIdentity || '',
      ipAddress: deviceInfo.ipAddress,
      timestamp: new Date(),
      failedAttempts: user.failedLoginAttempts,
    });

    // Create session with appropriate trust level
    const session = await this.sessionManager.createSession(
      user.id,
      riskScore.trustLevel,
      deviceIdentity || '',
      deviceInfo.ipAddress
    );

    // Update last login timestamp
    await this.updateLastLogin(user.id);

    return {
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      trustLevel: riskScore.trustLevel,
      requiresMFA: false,
      expiresIn: 15 * 60, // 15 minutes
    };
  }

  /**
   * Logout user by revoking session
   */
  async logout(sessionId: string): Promise<void> {
    await this.sessionManager.revokeSession(sessionId);
  }

  /**
   * Check if IP address has exceeded rate limit
   * Returns status object with requiresCaptcha flag
   */
  private checkRateLimit(ipAddress: string): { requiresCaptcha: boolean } {
    const entry = this.ipRateLimits.get(ipAddress);

    if (!entry) {
      return { requiresCaptcha: false };
    }

    const timeSinceLastAttempt = Date.now() - entry.lastAttempt.getTime();

    // Reset if outside rate limit window
    if (timeSinceLastAttempt > this.RATE_LIMIT_WINDOW) {
      this.ipRateLimits.delete(ipAddress);
      return { requiresCaptcha: false };
    }

    // Check if rate limit exceeded (takes priority over CAPTCHA)
    if (entry.attempts >= this.MAX_FAILED_ATTEMPTS) {
      throw new Error('Rate limit exceeded. Please try again later.');
    }

    // Return CAPTCHA status without throwing
    return { requiresCaptcha: entry.requiresCaptcha };
  }

  /**
   * Record a failed authentication attempt for an IP address
   */
  private recordFailedAttempt(ipAddress: string): void {
    const entry = this.ipRateLimits.get(ipAddress);

    if (!entry) {
      this.ipRateLimits.set(ipAddress, {
        attempts: 1,
        lastAttempt: new Date(),
        requiresCaptcha: false,
      });
      return;
    }

    const newAttempts = entry.attempts + 1;
    const requiresCaptcha = newAttempts >= this.CAPTCHA_THRESHOLD;

    this.ipRateLimits.set(ipAddress, {
      attempts: newAttempts,
      lastAttempt: new Date(),
      requiresCaptcha,
    });

    // Implement progressive delay
    // Note: In a real implementation, this would be handled by middleware
    // or a more sophisticated rate limiting system with actual delays
    // Progressive delay calculation: Math.min(newAttempts * 1000, 10000) ms
  }

  /**
   * Reset rate limit for an IP address after successful authentication
   */
  private resetRateLimit(ipAddress: string): void {
    this.ipRateLimits.delete(ipAddress);
  }

  /**
   * Get user by email
   */
  private async getUserByEmail(email: string): Promise<User | null> {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRowToUser(result.rows[0]);
  }

  /**
   * Get user by ID
   */
  private async getUserById(userId: string): Promise<User | null> {
    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRowToUser(result.rows[0]);
  }

  /**
   * Increment failed login attempts for a user
   */
  private async incrementFailedAttempts(userId: string): Promise<void> {
    const result = await pool.query(
      `UPDATE users 
       SET failed_login_attempts = failed_login_attempts + 1,
           last_failed_login_at = CURRENT_TIMESTAMP
       WHERE id = $1
       RETURNING failed_login_attempts`,
      [userId]
    );

    const failedAttempts = result.rows[0]?.failed_login_attempts || 0;

    // Lock account after threshold
    if (failedAttempts >= 5) {
      const lockoutDuration = 15 * 60 * 1000; // 15 minutes
      const lockoutUntil = new Date(Date.now() + lockoutDuration);

      await pool.query(
        `UPDATE users 
         SET account_locked = true, lockout_until = $1
         WHERE id = $2`,
        [lockoutUntil, userId]
      );
    }
  }

  /**
   * Reset failed login attempts for a user
   */
  private async resetFailedAttempts(userId: string): Promise<void> {
    await pool.query(
      `UPDATE users 
       SET failed_login_attempts = 0,
           last_failed_login_at = NULL,
           account_locked = false,
           lockout_until = NULL
       WHERE id = $1`,
      [userId]
    );
  }

  /**
   * Update last login timestamp
   */
  private async updateLastLogin(userId: string): Promise<void> {
    await pool.query(
      'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = $1',
      [userId]
    );
  }

  /**
   * Map database row to User object
   */
  private mapRowToUser(row: any): User {
    return {
      id: row.id,
      email: row.email,
      passwordHash: row.password_hash,
      mfaEnabled: row.mfa_enabled,
      mfaSecret: row.mfa_secret,
      deviceTrackingEnabled: row.device_tracking_enabled ?? true,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
      lastLoginAt: row.last_login_at ? new Date(row.last_login_at) : undefined,
      failedLoginAttempts: row.failed_login_attempts,
      lastFailedLoginAt: row.last_failed_login_at
        ? new Date(row.last_failed_login_at)
        : undefined,
      accountLocked: row.account_locked,
      lockoutUntil: row.lockout_until ? new Date(row.lockout_until) : undefined,
    };
  }

  /**
   * Extract device type from user agent
   */
  private extractDeviceType(userAgent: string): string {
    if (/mobile/i.test(userAgent)) return 'Mobile';
    if (/tablet/i.test(userAgent)) return 'Tablet';
    return 'Desktop';
  }

  /**
   * Extract browser from user agent
   */
  private extractBrowser(userAgent: string): string {
    if (/chrome/i.test(userAgent)) return 'Chrome';
    if (/firefox/i.test(userAgent)) return 'Firefox';
    if (/safari/i.test(userAgent)) return 'Safari';
    if (/edge/i.test(userAgent)) return 'Edge';
    return 'Unknown';
  }

  /**
   * Extract operating system from user agent
   */
  private extractOS(userAgent: string): string {
    if (/windows/i.test(userAgent)) return 'Windows';
    if (/mac/i.test(userAgent)) return 'macOS';
    if (/linux/i.test(userAgent)) return 'Linux';
    if (/android/i.test(userAgent)) return 'Android';
    if (/ios/i.test(userAgent)) return 'iOS';
    return 'Unknown';
  }
}
