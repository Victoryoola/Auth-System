import crypto from 'crypto';
import { pool } from '../config/database';
import { Challenge, CreateChallengeInput } from '../models/Challenge';
import { VerificationMethod } from '../types/enums';
import { SessionManager } from './SessionManager';
import { SessionTrustLevel } from '../types/enums';

/**
 * Verification result
 */
export interface VerificationResult {
  success: boolean;
  newTrustLevel?: SessionTrustLevel;
  reason?: string;
}

/**
 * Email service interface for OTP delivery
 */
export interface EmailService {
  sendOTP(email: string, otp: string): Promise<void>;
}

/**
 * SMS service interface for OTP delivery
 */
export interface SMSService {
  sendOTP(phoneNumber: string, otp: string): Promise<void>;
}

/**
 * Redis client interface for rate limiting
 */
interface RedisClient {
  get(key: string): Promise<string | null>;
  setEx(key: string, seconds: number, value: string): Promise<void>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<void>;
}

/**
 * Step-Up Verifier service
 * Handles OTP generation, delivery, and verification for step-up authentication
 */
export class StepUpVerifier {
  private otpExpiry = 10 * 60; // 10 minutes in seconds
  private maxAttempts = 3;
  private rateLimitWindow = 60 * 60; // 1 hour in seconds
  private rateLimitMax = 5; // 5 challenges per hour
  private sessionManager: SessionManager;
  private emailService?: EmailService;
  private smsService?: SMSService;
  private redisClient?: RedisClient;

  constructor(
    sessionManager: SessionManager,
    emailService?: EmailService,
    smsService?: SMSService,
    redisClient?: RedisClient
  ) {
    this.sessionManager = sessionManager;
    this.emailService = emailService;
    this.smsService = smsService;
    this.redisClient = redisClient;
  }

  /**
   * Generate a cryptographically secure 6-digit OTP
   */
  private generateOTP(): string {
    // Generate random bytes and convert to 6-digit number
    const randomBytes = crypto.randomBytes(4);
    const randomNumber = randomBytes.readUInt32BE(0);
    const otp = (randomNumber % 1000000).toString().padStart(6, '0');
    return otp;
  }

  /**
   * Hash OTP for secure storage
   */
  private hashOTP(otp: string): string {
    return crypto.createHash('sha256').update(otp).digest('hex');
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  private constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }

  /**
   * Check rate limit for user
   */
  private async checkRateLimit(userId: string): Promise<boolean> {
    if (!this.redisClient) {
      return true; // No rate limiting if Redis not available
    }

    const rateLimitKey = `stepup:ratelimit:${userId}`;
    const count = await this.redisClient.get(rateLimitKey);

    if (count && parseInt(count) >= this.rateLimitMax) {
      return false;
    }

    return true;
  }

  /**
   * Increment rate limit counter
   */
  private async incrementRateLimit(userId: string): Promise<void> {
    if (!this.redisClient) {
      return;
    }

    const rateLimitKey = `stepup:ratelimit:${userId}`;
    const count = await this.redisClient.incr(rateLimitKey);

    // Set expiry on first increment
    if (count === 1) {
      await this.redisClient.expire(rateLimitKey, this.rateLimitWindow);
    }
  }

  /**
   * Get user email from database
   */
  private async getUserEmail(userId: string): Promise<string | null> {
    const result = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
    return result.rows.length > 0 ? result.rows[0].email : null;
  }

  /**
   * Get user phone number from database (placeholder - assumes phone field exists)
   */
  private async getUserPhone(userId: string): Promise<string | null> {
    // Note: This assumes a phone_number field exists in users table
    // In a real implementation, this would need to be added to the schema
    const result = await pool.query(
      'SELECT phone_number FROM users WHERE id = $1',
      [userId]
    );
    return result.rows.length > 0 ? result.rows[0].phone_number : null;
  }

  /**
   * Initiate step-up verification
   */
  async initiateVerification(
    userId: string,
    sessionId: string,
    method: VerificationMethod
  ): Promise<Challenge> {
    // Check rate limit
    const withinLimit = await this.checkRateLimit(userId);
    if (!withinLimit) {
      throw new Error('Rate limit exceeded. Please try again later.');
    }

    // Generate OTP
    const otp = this.generateOTP();
    const otpHash = this.hashOTP(otp);

    // Create challenge
    const challengeId = crypto.randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.otpExpiry * 1000);

    const challengeInput: CreateChallengeInput = {
      userId,
      sessionId,
      method,
      otpHash,
      expiresAt,
      attemptsRemaining: this.maxAttempts,
    };

    await pool.query(
      `INSERT INTO challenges (
        id, user_id, session_id, method, otp_hash, created_at,
        expires_at, attempts_remaining, verified
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        challengeId,
        challengeInput.userId,
        challengeInput.sessionId,
        challengeInput.method,
        challengeInput.otpHash,
        now,
        challengeInput.expiresAt,
        challengeInput.attemptsRemaining,
        false,
      ]
    );

    // Send OTP based on method
    try {
      if (method === VerificationMethod.EMAIL_OTP) {
        const email = await this.getUserEmail(userId);
        if (!email) {
          throw new Error('User email not found');
        }
        if (!this.emailService) {
          throw new Error('Email service not configured');
        }
        await this.emailService.sendOTP(email, otp);
      } else if (method === VerificationMethod.SMS_OTP) {
        const phone = await this.getUserPhone(userId);
        if (!phone) {
          throw new Error('User phone number not found');
        }
        if (!this.smsService) {
          throw new Error('SMS service not configured');
        }
        await this.smsService.sendOTP(phone, otp);
      } else if (method === VerificationMethod.AUTHENTICATOR_APP) {
        // Authenticator app doesn't need OTP delivery
        // The user generates the code from their app
      }
    } catch (error) {
      // Clean up challenge if delivery fails
      await pool.query('DELETE FROM challenges WHERE id = $1', [challengeId]);
      throw error;
    }

    // Increment rate limit counter
    await this.incrementRateLimit(userId);

    // Return challenge
    const result = await pool.query('SELECT * FROM challenges WHERE id = $1', [challengeId]);
    return this.mapRowToChallenge(result.rows[0]);
  }

  /**
   * Verify challenge with OTP
   */
  async verifyChallenge(challengeId: string, otp: string): Promise<VerificationResult> {
    // Retrieve challenge
    const result = await pool.query('SELECT * FROM challenges WHERE id = $1', [challengeId]);

    if (result.rows.length === 0) {
      return {
        success: false,
        reason: 'Challenge not found',
      };
    }

    const challenge = this.mapRowToChallenge(result.rows[0]);

    // Check if already verified
    if (challenge.verified) {
      return {
        success: false,
        reason: 'Challenge already verified',
      };
    }

    // Check if expired
    if (challenge.expiresAt < new Date()) {
      return {
        success: false,
        reason: 'Challenge expired',
      };
    }

    // Check attempts remaining
    if (challenge.attemptsRemaining <= 0) {
      return {
        success: false,
        reason: 'Maximum attempts exceeded',
      };
    }

    // Verify OTP using constant-time comparison
    const otpHash = this.hashOTP(otp);
    const isValid = this.constantTimeCompare(otpHash, challenge.otpHash || '');

    if (!isValid) {
      // Decrement attempts
      await pool.query(
        'UPDATE challenges SET attempts_remaining = attempts_remaining - 1 WHERE id = $1',
        [challengeId]
      );

      return {
        success: false,
        reason: 'Invalid OTP',
      };
    }

    // Mark challenge as verified
    await pool.query('UPDATE challenges SET verified = true WHERE id = $1', [challengeId]);

    // Promote session trust level
    const newTrustLevel = await this.determineNewTrustLevel(challenge.sessionId);
    await this.sessionManager.promoteTrustLevel(challenge.sessionId, newTrustLevel);

    return {
      success: true,
      newTrustLevel,
    };
  }

  /**
   * Resend OTP for existing challenge
   */
  async resendChallenge(challengeId: string): Promise<void> {
    // Retrieve challenge
    const result = await pool.query('SELECT * FROM challenges WHERE id = $1', [challengeId]);

    if (result.rows.length === 0) {
      throw new Error('Challenge not found');
    }

    const challenge = this.mapRowToChallenge(result.rows[0]);

    // Check if expired
    if (challenge.expiresAt < new Date()) {
      throw new Error('Challenge expired. Please initiate a new verification.');
    }

    // Check if already verified
    if (challenge.verified) {
      throw new Error('Challenge already verified');
    }

    // Check rate limit
    const withinLimit = await this.checkRateLimit(challenge.userId);
    if (!withinLimit) {
      throw new Error('Rate limit exceeded. Please try again later.');
    }

    // Generate new OTP
    const otp = this.generateOTP();
    const otpHash = this.hashOTP(otp);

    // Update challenge with new OTP
    await pool.query('UPDATE challenges SET otp_hash = $1 WHERE id = $2', [otpHash, challengeId]);

    // Send OTP based on method
    if (challenge.method === VerificationMethod.EMAIL_OTP) {
      const email = await this.getUserEmail(challenge.userId);
      if (!email) {
        throw new Error('User email not found');
      }
      if (!this.emailService) {
        throw new Error('Email service not configured');
      }
      await this.emailService.sendOTP(email, otp);
    } else if (challenge.method === VerificationMethod.SMS_OTP) {
      const phone = await this.getUserPhone(challenge.userId);
      if (!phone) {
        throw new Error('User phone number not found');
      }
      if (!this.smsService) {
        throw new Error('SMS service not configured');
      }
      await this.smsService.sendOTP(phone, otp);
    }

    // Increment rate limit counter
    await this.incrementRateLimit(challenge.userId);
  }

  /**
   * Determine new trust level after successful verification
   */
  private async determineNewTrustLevel(sessionId: string): Promise<SessionTrustLevel> {
    // Retrieve current session
    const result = await pool.query('SELECT trust_level FROM sessions WHERE id = $1', [sessionId]);

    if (result.rows.length === 0) {
      throw new Error('Session not found');
    }

    const currentLevel = result.rows[0].trust_level as SessionTrustLevel;

    // Promote trust level
    switch (currentLevel) {
      case SessionTrustLevel.HIGH_RISK:
        return SessionTrustLevel.UNVERIFIED;
      case SessionTrustLevel.UNVERIFIED:
        return SessionTrustLevel.LIMITED_TRUST;
      case SessionTrustLevel.LIMITED_TRUST:
        return SessionTrustLevel.FULL_TRUST;
      case SessionTrustLevel.FULL_TRUST:
        return SessionTrustLevel.FULL_TRUST; // Already at highest level
      default:
        return SessionTrustLevel.LIMITED_TRUST;
    }
  }

  /**
   * Map database row to Challenge object
   */
  private mapRowToChallenge(row: any): Challenge {
    return {
      id: row.id,
      userId: row.user_id,
      sessionId: row.session_id,
      method: row.method as VerificationMethod,
      otpHash: row.otp_hash,
      createdAt: new Date(row.created_at),
      expiresAt: new Date(row.expires_at),
      attemptsRemaining: row.attempts_remaining,
      verified: row.verified,
    };
  }
}
