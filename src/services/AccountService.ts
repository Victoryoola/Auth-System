import crypto from 'crypto';
import { pool } from '../config/database';

/**
 * Account Service
 * Handles account deletion and user preferences
 */
export class AccountService {
  /**
   * Delete user account and anonymize/remove associated data
   * Implements cascading deletion according to retention policies
   * 
   * @param userId - User ID to delete
   */
  async deleteAccount(userId: string): Promise<void> {
    const client = await pool.connect();
    
    try {
      await client.query('BEGIN');

      // 1. Delete sessions
      await client.query('DELETE FROM sessions WHERE user_id = $1', [userId]);

      // 2. Delete devices
      await client.query('DELETE FROM devices WHERE user_id = $1', [userId]);

      // 3. Delete risk evaluations
      await client.query('DELETE FROM risk_evaluations WHERE user_id = $1', [userId]);

      // 4. Delete challenges
      await client.query('DELETE FROM challenges WHERE user_id = $1', [userId]);

      // 5. Anonymize audit logs (keep for analytics but remove PII)
      const anonymizedId = this.generateAnonymizedId(userId);
      await client.query(
        'UPDATE audit_logs SET user_id = $1 WHERE user_id = $2',
        [anonymizedId, userId]
      );

      // 6. Delete user record
      await client.query('DELETE FROM users WHERE id = $1', [userId]);

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Update user device tracking preference
   * 
   * @param userId - User ID
   * @param enabled - Whether device tracking is enabled
   */
  async updateDeviceTrackingPreference(
    userId: string,
    enabled: boolean
  ): Promise<void> {
    const query = `
      UPDATE users 
      SET device_tracking_enabled = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
    `;
    
    await pool.query(query, [enabled, userId]);
  }

  /**
   * Get user device tracking preference
   * 
   * @param userId - User ID
   * @returns Device tracking enabled status
   */
  async getDeviceTrackingPreference(userId: string): Promise<boolean> {
    const query = 'SELECT device_tracking_enabled FROM users WHERE id = $1';
    const result = await pool.query(query, [userId]);
    
    if (result.rows.length === 0) {
      throw new Error('User not found');
    }
    
    return result.rows[0].device_tracking_enabled;
  }

  /**
   * Generate anonymized user ID for audit log retention
   * Uses SHA-256 hash with salt to prevent reverse lookup
   * 
   * @param userId - Original user ID
   * @returns Anonymized ID
   */
  private generateAnonymizedId(userId: string): string {
    const salt = 'audit_log_anonymization_salt';
    const hash = crypto.createHash('sha256');
    hash.update(userId + salt);
    return 'anon_' + hash.digest('hex').substring(0, 32);
  }
}
