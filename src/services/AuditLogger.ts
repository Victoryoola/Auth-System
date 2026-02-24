import crypto from 'crypto';
import { pool } from '../config/database';
import { AuditLog } from '../models/AuditLog';
import {
  AuthAttemptEvent,
  RiskEvaluationEvent,
  DeviceChangeEvent,
  SuspiciousActivityEvent,
  StepUpAttemptEvent,
  LogFilters,
} from '../types/audit';

/**
 * Audit Logger Service
 * Records authentication events, risk evaluations, device changes, and security events
 * Implements encryption for sensitive data and supports querying with user isolation
 */
export class AuditLogger {
  private encryptionKey: Buffer;
  private readonly algorithm = 'aes-256-gcm';

  constructor(encryptionKey?: string) {
    // Use provided key or generate from environment variable
    const key = encryptionKey || process.env.AUDIT_ENCRYPTION_KEY || this.generateDefaultKey();
    this.encryptionKey = Buffer.from(key, 'hex');
  }

  /**
   * Generate a default encryption key (for development only)
   * In production, this should be provided via environment variable
   */
  private generateDefaultKey(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Encrypt sensitive data using AES-256-GCM
   * 
   * @param data - Data to encrypt
   * @returns Encrypted data with IV and auth tag
   */
  private encrypt(data: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, this.encryptionKey, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Combine IV, auth tag, and encrypted data
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  /**
   * Decrypt sensitive data
   * 
   * @param encryptedData - Encrypted data with IV and auth tag
   * @returns Decrypted data
   */
  private decrypt(encryptedData: string): string {
    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];

    const decipher = crypto.createDecipheriv(this.algorithm, this.encryptionKey, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Log authentication attempt
   * Encrypts IP address and device identity before storage
   * Uses asynchronous logging via message queue pattern
   * 
   * @param event - Authentication attempt event
   */
  async logAuthAttempt(event: AuthAttemptEvent): Promise<void> {
    // Encrypt sensitive fields
    const encryptedIp = this.encrypt(event.ipAddress);
    const encryptedDevice = this.encrypt(event.deviceIdentity);

    const details = {
      success: event.success,
      failureReason: event.failureReason,
      encryptedIpAddress: encryptedIp,
      encryptedDeviceIdentity: encryptedDevice,
    };

    // Asynchronous logging - fire and forget pattern
    setImmediate(async () => {
      try {
        await this.insertLog({
          eventType: 'AUTH_ATTEMPT',
          userId: event.userId,
          timestamp: event.timestamp,
          success: event.success,
          details,
          encryptedFields: ['ipAddress', 'deviceIdentity'],
        });
      } catch (error) {
        console.error('Failed to log auth attempt:', error);
      }
    });
  }

  /**
   * Log risk evaluation
   * Records risk score, contributing factors, and assigned trust level
   * 
   * @param event - Risk evaluation event
   */
  async logRiskEvaluation(event: RiskEvaluationEvent): Promise<void> {
    const details = {
      riskScore: event.riskScore,
      trustLevel: event.trustLevel,
      factors: event.factors.map(f => ({
        name: f.name,
        weight: f.weight,
        contribution: f.contribution,
        details: f.details,
      })),
    };

    setImmediate(async () => {
      try {
        await this.insertLog({
          eventType: 'RISK_EVALUATION',
          userId: event.userId,
          timestamp: event.timestamp,
          success: true,
          details,
          encryptedFields: [],
        });
      } catch (error) {
        console.error('Failed to log risk evaluation:', error);
      }
    });
  }

  /**
   * Log device trust status change
   * Records device changes including trust status updates and revocations
   * 
   * @param event - Device change event
   */
  async logDeviceChange(event: DeviceChangeEvent): Promise<void> {
    const encryptedDevice = this.encrypt(event.deviceIdentity);

    const details = {
      changeType: event.changeType,
      oldStatus: event.oldStatus,
      newStatus: event.newStatus,
      encryptedDeviceIdentity: encryptedDevice,
    };

    setImmediate(async () => {
      try {
        await this.insertLog({
          eventType: 'DEVICE_CHANGE',
          userId: event.userId,
          timestamp: event.timestamp,
          success: true,
          details,
          encryptedFields: ['deviceIdentity'],
        });
      } catch (error) {
        console.error('Failed to log device change:', error);
      }
    });
  }

  /**
   * Log suspicious activity
   * Records security events and risk indicators
   * 
   * @param event - Suspicious activity event
   */
  async logSuspiciousActivity(event: SuspiciousActivityEvent): Promise<void> {
    const details = {
      activityType: event.activityType,
      details: event.details,
      riskIndicators: event.riskIndicators,
    };

    setImmediate(async () => {
      try {
        await this.insertLog({
          eventType: 'SUSPICIOUS_ACTIVITY',
          userId: event.userId,
          timestamp: event.timestamp,
          success: false,
          details,
          encryptedFields: [],
        });
      } catch (error) {
        console.error('Failed to log suspicious activity:', error);
      }
    });
  }

  /**
   * Log step-up authentication attempt
   * Records verification method, outcome, and session ID
   * 
   * @param event - Step-up attempt event
   */
  async logStepUpAttempt(event: StepUpAttemptEvent): Promise<void> {
    const details = {
      method: event.method,
      success: event.success,
      sessionId: event.sessionId,
    };

    setImmediate(async () => {
      try {
        await this.insertLog({
          eventType: 'STEP_UP_ATTEMPT',
          userId: event.userId,
          timestamp: event.timestamp,
          success: event.success,
          details,
          encryptedFields: [],
        });
      } catch (error) {
        console.error('Failed to log step-up attempt:', error);
      }
    });
  }

  /**
   * Insert audit log into database
   * 
   * @param log - Log entry to insert
   */
  private async insertLog(log: {
    eventType: string;
    userId: string;
    timestamp: Date;
    success: boolean;
    details: Record<string, unknown>;
    encryptedFields: string[];
    sessionId?: string;
    deviceIdentity?: string;
    ipAddress?: string;
  }): Promise<void> {
    const query = `
      INSERT INTO audit_logs (
        event_type,
        user_id,
        timestamp,
        success,
        details,
        encrypted_fields,
        session_id,
        device_identity,
        ip_address
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `;

    await pool.query(query, [
      log.eventType,
      log.userId,
      log.timestamp,
      log.success,
      JSON.stringify(log.details),
      log.encryptedFields,
      log.sessionId || null,
      log.deviceIdentity || null,
      log.ipAddress || null,
    ]);
  }

  /**
   * Query audit logs with user isolation
   * Only returns logs for the specified user
   * Decrypts sensitive fields before returning
   * 
   * @param userId - User ID to query logs for
   * @param filters - Optional filters for the query
   * @returns Array of audit logs
   */
  async queryLogs(userId: string, filters: LogFilters = {}): Promise<AuditLog[]> {
    let query = `
      SELECT * FROM audit_logs
      WHERE user_id = $1
    `;
    
    const params: any[] = [userId];
    let paramIndex = 2;

    // Apply filters
    if (filters.eventType) {
      query += ` AND event_type = $${paramIndex}`;
      params.push(filters.eventType);
      paramIndex++;
    }

    if (filters.startDate) {
      query += ` AND timestamp >= $${paramIndex}`;
      params.push(filters.startDate);
      paramIndex++;
    }

    if (filters.endDate) {
      query += ` AND timestamp <= $${paramIndex}`;
      params.push(filters.endDate);
      paramIndex++;
    }

    if (filters.success !== undefined) {
      query += ` AND success = $${paramIndex}`;
      params.push(filters.success);
      paramIndex++;
    }

    // Order by timestamp descending
    query += ` ORDER BY timestamp DESC`;

    // Apply pagination
    if (filters.limit) {
      query += ` LIMIT $${paramIndex}`;
      params.push(filters.limit);
      paramIndex++;
    }

    if (filters.offset) {
      query += ` OFFSET $${paramIndex}`;
      params.push(filters.offset);
      paramIndex++;
    }

    const result = await pool.query(query, params);

    return result.rows.map(row => this.mapRowToAuditLog(row));
  }

  /**
   * Enforce retention policy by deleting old logs
   * Different retention periods for different event types
   */
  async enforceRetentionPolicy(): Promise<void> {
    const retentionPolicies = {
      AUTH_ATTEMPT: 90,
      RISK_EVALUATION: 30,
      DEVICE_CHANGE: 365,
      SUSPICIOUS_ACTIVITY: 365,
      STEP_UP_ATTEMPT: 90,
    };

    for (const [eventType, days] of Object.entries(retentionPolicies)) {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - days);

      const query = `
        DELETE FROM audit_logs
        WHERE event_type = $1 AND timestamp < $2
      `;

      await pool.query(query, [eventType, cutoffDate]);
    }
  }

  /**
   * Map database row to AuditLog model
   * Decrypts sensitive fields if present
   * 
   * @param row - Database row
   * @returns AuditLog object
   */
  private mapRowToAuditLog(row: any): AuditLog {
    const details = typeof row.details === 'string' 
      ? JSON.parse(row.details) 
      : row.details;

    // Decrypt sensitive fields if present
    if (details.encryptedIpAddress) {
      try {
        details.ipAddress = this.decrypt(details.encryptedIpAddress);
        delete details.encryptedIpAddress;
      } catch (error) {
        console.error('Failed to decrypt IP address:', error);
      }
    }

    if (details.encryptedDeviceIdentity) {
      try {
        details.deviceIdentity = this.decrypt(details.encryptedDeviceIdentity);
        delete details.encryptedDeviceIdentity;
      } catch (error) {
        console.error('Failed to decrypt device identity:', error);
      }
    }

    return {
      id: row.id,
      timestamp: new Date(row.timestamp),
      eventType: row.event_type,
      userId: row.user_id,
      sessionId: row.session_id,
      deviceIdentity: row.device_identity,
      ipAddress: row.ip_address,
      success: row.success,
      details,
      encryptedFields: row.encrypted_fields || [],
    };
  }
}
