import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { pool } from '../config/database';
import { Session, CreateSessionInput } from '../models/Session';
import { SessionTrustLevel } from '../types/enums';

/**
 * Session validation result
 */
export interface SessionValidation {
  valid: boolean;
  session?: Session;
  reason?: string;
}

/**
 * Token refresh result
 */
export interface RefreshResult {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/**
 * JWT payload structure
 */
interface TokenPayload {
  sessionId: string;
  userId: string;
  trustLevel: SessionTrustLevel;
  deviceIdentity: string;
  jti: string;
  iat: number;
  exp: number;
}

/**
 * Redis client interface for token replay protection
 */
interface RedisClient {
  get(key: string): Promise<string | null>;
  setEx(key: string, seconds: number, value: string): Promise<void>;
  del(key: string): Promise<void>;
}

/**
 * Session Manager service
 * Handles token generation, validation, session lifecycle, and replay protection
 */
export class SessionManager {
  private accessTokenExpiry = 15 * 60; // 15 minutes in seconds
  private refreshTokenExpiry = 7 * 24 * 60 * 60; // 7 days in seconds
  private privateKey: string;
  private publicKey: string;
  private redisClient: RedisClient | null;

  constructor(privateKey: string, publicKey: string, redisClient?: RedisClient) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.redisClient = redisClient || null;
  }

  /**
   * Generate a cryptographically secure random token ID (jti)
   */
  private generateJti(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Generate a cryptographically secure refresh token
   */
  private generateRefreshToken(): string {
    return crypto.randomBytes(64).toString('hex');
  }

  /**
   * Hash a token for storage
   */
  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Generate access token (JWT)
   */
  private generateAccessToken(
    sessionId: string,
    userId: string,
    trustLevel: SessionTrustLevel,
    deviceIdentity: string,
    jti: string
  ): string {
    const payload: Omit<TokenPayload, 'iat' | 'exp'> = {
      sessionId,
      userId,
      trustLevel,
      deviceIdentity,
      jti,
    };

    return jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      expiresIn: this.accessTokenExpiry,
    });
  }

  /**
   * Validate access token signature and expiration
   */
  async validateToken(accessToken: string): Promise<SessionValidation> {
    try {
      // Verify token signature and expiration
      const decoded = jwt.verify(accessToken, this.publicKey, {
        algorithms: ['RS256'],
      }) as TokenPayload;

      // Check for token replay if Redis is available
      if (this.redisClient) {
        const replayKey = `token:used:${decoded.jti}`;
        const isUsed = await this.redisClient.get(replayKey);
        
        if (isUsed) {
          return {
            valid: false,
            reason: 'Token replay detected',
          };
        }

        // Mark token as used with TTL matching token expiry
        const ttl = decoded.exp - Math.floor(Date.now() / 1000);
        if (ttl > 0) {
          await this.redisClient.setEx(replayKey, ttl, '1');
        }
      }

      // Retrieve session from database
      const result = await pool.query(
        'SELECT * FROM sessions WHERE id = $1 AND revoked = false',
        [decoded.sessionId]
      );

      if (result.rows.length === 0) {
        return {
          valid: false,
          reason: 'Session not found or revoked',
        };
      }

      const session = this.mapRowToSession(result.rows[0]);

      // Check if access token has expired in database
      if (session.accessTokenExpiry < new Date()) {
        return {
          valid: false,
          reason: 'Token expired',
        };
      }

      return {
        valid: true,
        session,
      };
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return {
          valid: false,
          reason: 'Token expired',
        };
      }
      if (error instanceof jwt.JsonWebTokenError) {
        return {
          valid: false,
          reason: 'Invalid token signature',
        };
      }
      return {
        valid: false,
        reason: 'Token validation failed',
      };
    }
  }

  /**
   * Create a new session with tokens
   */
  async createSession(
    userId: string,
    trustLevel: SessionTrustLevel,
    deviceIdentity: string,
    ipAddress: string
  ): Promise<Session & { accessToken: string; refreshToken: string }> {
    const sessionId = crypto.randomUUID();
    const jti = this.generateJti();
    const refreshToken = this.generateRefreshToken();
    const refreshTokenFamily = crypto.randomUUID();

    const accessToken = this.generateAccessToken(
      sessionId,
      userId,
      trustLevel,
      deviceIdentity,
      jti
    );

    const now = new Date();
    const accessTokenExpiry = new Date(now.getTime() + this.accessTokenExpiry * 1000);
    const refreshTokenExpiry = new Date(now.getTime() + this.refreshTokenExpiry * 1000);

    const sessionInput: CreateSessionInput = {
      userId,
      trustLevel,
      deviceIdentity,
      accessTokenHash: this.hashToken(accessToken),
      refreshTokenHash: this.hashToken(refreshToken),
      refreshTokenFamily,
      accessTokenExpiry,
      refreshTokenExpiry,
      ipAddress,
    };

    const result = await pool.query(
      `INSERT INTO sessions (
        id, user_id, trust_level, device_identity, access_token_hash,
        refresh_token_hash, refresh_token_family, access_token_expiry,
        refresh_token_expiry, created_at, last_activity, ip_address, revoked
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING *`,
      [
        sessionId,
        sessionInput.userId,
        sessionInput.trustLevel,
        sessionInput.deviceIdentity,
        sessionInput.accessTokenHash,
        sessionInput.refreshTokenHash,
        sessionInput.refreshTokenFamily,
        sessionInput.accessTokenExpiry,
        sessionInput.refreshTokenExpiry,
        now,
        now,
        sessionInput.ipAddress,
        false,
      ]
    );

    const session = this.mapRowToSession(result.rows[0]);

    return {
      ...session,
      accessToken,
      refreshToken,
    };
  }

  /**
   * Refresh session tokens with token rotation
   */
  async refreshSession(refreshToken: string): Promise<RefreshResult> {
    const refreshTokenHash = this.hashToken(refreshToken);

    // Find session by refresh token hash
    const result = await pool.query(
      `SELECT * FROM sessions 
       WHERE refresh_token_hash = $1 AND revoked = false`,
      [refreshTokenHash]
    );

    if (result.rows.length === 0) {
      // Potential replay attack - invalidate all sessions in the token family
      const familyResult = await pool.query(
        'SELECT refresh_token_family FROM sessions WHERE refresh_token_hash = $1',
        [refreshTokenHash]
      );

      if (familyResult.rows.length > 0) {
        const family = familyResult.rows[0].refresh_token_family;
        await pool.query(
          'UPDATE sessions SET revoked = true WHERE refresh_token_family = $1',
          [family]
        );
      }

      throw new Error('Invalid refresh token - potential replay attack detected');
    }

    const session = this.mapRowToSession(result.rows[0]);

    // Check if refresh token has expired
    if (session.refreshTokenExpiry < new Date()) {
      throw new Error('Refresh token expired');
    }

    // Generate new tokens
    const newJti = this.generateJti();
    const newRefreshToken = this.generateRefreshToken();
    const newAccessToken = this.generateAccessToken(
      session.id,
      session.userId,
      session.trustLevel,
      session.deviceIdentity,
      newJti
    );

    const now = new Date();
    const newAccessTokenExpiry = new Date(now.getTime() + this.accessTokenExpiry * 1000);
    const newRefreshTokenExpiry = new Date(now.getTime() + this.refreshTokenExpiry * 1000);

    // Update session with new tokens (token rotation)
    await pool.query(
      `UPDATE sessions 
       SET access_token_hash = $1, 
           refresh_token_hash = $2,
           access_token_expiry = $3,
           refresh_token_expiry = $4,
           last_activity = $5
       WHERE id = $6`,
      [
        this.hashToken(newAccessToken),
        this.hashToken(newRefreshToken),
        newAccessTokenExpiry,
        newRefreshTokenExpiry,
        now,
        session.id,
      ]
    );

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: this.accessTokenExpiry,
    };
  }

  /**
   * Promote session trust level (for step-up authentication)
   */
  async promoteTrustLevel(sessionId: string, newLevel: SessionTrustLevel): Promise<void> {
    await pool.query(
      'UPDATE sessions SET trust_level = $1, last_activity = $2 WHERE id = $3',
      [newLevel, new Date(), sessionId]
    );
  }

  /**
   * Get all active sessions for a user
   */
  async getActiveSessions(userId: string): Promise<Session[]> {
    const result = await pool.query(
      'SELECT * FROM sessions WHERE user_id = $1 AND revoked = false ORDER BY last_activity DESC',
      [userId]
    );

    return result.rows.map(this.mapRowToSession);
  }

  /**
   * Revoke a specific session
   */
  async revokeSession(sessionId: string): Promise<void> {
    await pool.query('UPDATE sessions SET revoked = true WHERE id = $1', [sessionId]);

    // Clear token replay cache if Redis is available
    if (this.redisClient) {
      const result = await pool.query('SELECT * FROM sessions WHERE id = $1', [sessionId]);
      if (result.rows.length > 0) {
        // Note: We can't extract jti from stored hash, but the token will be rejected
        // when validated due to revoked status
      }
    }
  }

  /**
   * Revoke all sessions for a specific device
   */
  async revokeDeviceSessions(deviceIdentity: string): Promise<void> {
    await pool.query(
      'UPDATE sessions SET revoked = true WHERE device_identity = $1',
      [deviceIdentity]
    );
  }

  /**
   * Map database row to Session object
   */
  private mapRowToSession(row: any): Session {
    return {
      id: row.id,
      userId: row.user_id,
      trustLevel: row.trust_level as SessionTrustLevel,
      deviceIdentity: row.device_identity,
      accessTokenHash: row.access_token_hash,
      refreshTokenHash: row.refresh_token_hash,
      refreshTokenFamily: row.refresh_token_family,
      accessTokenExpiry: new Date(row.access_token_expiry),
      refreshTokenExpiry: new Date(row.refresh_token_expiry),
      createdAt: new Date(row.created_at),
      lastActivity: new Date(row.last_activity),
      ipAddress: row.ip_address,
      revoked: row.revoked,
    };
  }
}
