import { AuditLogger } from './AuditLogger';
import { pool } from '../config/database';
import {
  AuthAttemptEvent,
  RiskEvaluationEvent,
  DeviceChangeEvent,
  SuspiciousActivityEvent,
  StepUpAttemptEvent,
} from '../types/audit';
import { SessionTrustLevel, VerificationMethod, TrustStatus } from '../types/enums';
import * as fc from 'fast-check';

// Mock the database pool
jest.mock('../config/database', () => ({
  pool: {
    query: jest.fn(),
    connect: jest.fn(),
  },
}));

const mockPoolQuery = pool.query as jest.Mock;

describe('AuditLogger', () => {
  let auditLogger: AuditLogger;

  beforeEach(() => {
    jest.clearAllMocks();
    // Use a fixed encryption key for testing
    const testKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    auditLogger = new AuditLogger(testKey);
  });

  describe('logAuthAttempt', () => {
    it('should log successful authentication attempt', async () => {
      const event: AuthAttemptEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        ipAddress: '192.168.1.1',
        success: true,
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logAuthAttempt(event);

      // Wait for async logging
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO audit_logs'),
        expect.arrayContaining([
          'AUTH_ATTEMPT',
          'user-123',
          event.timestamp,
          true,
          expect.any(String),
          ['ipAddress', 'deviceIdentity'],
        ])
      );
    });

    it('should log failed authentication attempt with reason', async () => {
      const event: AuthAttemptEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        ipAddress: '192.168.1.1',
        success: false,
        failureReason: 'Invalid password',
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logAuthAttempt(event);

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockPoolQuery).toHaveBeenCalled();
      const callArgs = mockPoolQuery.mock.calls[0];
      const details = JSON.parse(callArgs[1][4]);
      expect(details.failureReason).toBe('Invalid password');
    });

    it('should encrypt IP address and device identity', async () => {
      const event: AuthAttemptEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        ipAddress: '192.168.1.1',
        success: true,
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logAuthAttempt(event);

      await new Promise(resolve => setTimeout(resolve, 100));

      const callArgs = mockPoolQuery.mock.calls[0];
      const details = JSON.parse(callArgs[1][4]);
      
      // Encrypted data should not match original
      expect(details.encryptedIpAddress).not.toBe('192.168.1.1');
      expect(details.encryptedDeviceIdentity).not.toBe('device-abc');
      
      // Encrypted data should have the format: iv:authTag:encrypted
      expect(details.encryptedIpAddress).toMatch(/^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
      expect(details.encryptedDeviceIdentity).toMatch(/^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
    });
  });

  describe('logRiskEvaluation', () => {
    it('should log risk evaluation with all factors', async () => {
      const event: RiskEvaluationEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        riskScore: 45,
        trustLevel: SessionTrustLevel.UNVERIFIED,
        factors: [
          {
            name: 'deviceFamiliarity',
            weight: 0.3,
            contribution: 15,
            details: 'Unknown device',
          },
          {
            name: 'geographicAnomaly',
            weight: 0.2,
            contribution: 10,
            details: 'Different country',
          },
        ],
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logRiskEvaluation(event);

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO audit_logs'),
        expect.arrayContaining([
          'RISK_EVALUATION',
          'user-123',
          event.timestamp,
          true,
        ])
      );

      const callArgs = mockPoolQuery.mock.calls[0];
      const details = JSON.parse(callArgs[1][4]);
      expect(details.riskScore).toBe(45);
      expect(details.trustLevel).toBe(SessionTrustLevel.UNVERIFIED);
      expect(details.factors).toHaveLength(2);
    });
  });

  describe('logDeviceChange', () => {
    it('should log device registration', async () => {
      const event: DeviceChangeEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        changeType: 'REGISTER',
        newStatus: TrustStatus.UNTRUSTED,
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logDeviceChange(event);

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO audit_logs'),
        expect.arrayContaining(['DEVICE_CHANGE', 'user-123'])
      );
    });

    it('should log device trust status change', async () => {
      const event: DeviceChangeEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        changeType: 'TRUST',
        oldStatus: TrustStatus.UNTRUSTED,
        newStatus: TrustStatus.TRUSTED,
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logDeviceChange(event);

      await new Promise(resolve => setTimeout(resolve, 100));

      const callArgs = mockPoolQuery.mock.calls[0];
      const details = JSON.parse(callArgs[1][4]);
      expect(details.changeType).toBe('TRUST');
      expect(details.oldStatus).toBe(TrustStatus.UNTRUSTED);
      expect(details.newStatus).toBe(TrustStatus.TRUSTED);
    });

    it('should encrypt device identity', async () => {
      const event: DeviceChangeEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        changeType: 'REVOKE',
        oldStatus: TrustStatus.TRUSTED,
        newStatus: TrustStatus.UNTRUSTED,
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logDeviceChange(event);

      await new Promise(resolve => setTimeout(resolve, 100));

      const callArgs = mockPoolQuery.mock.calls[0];
      const details = JSON.parse(callArgs[1][4]);
      expect(details.encryptedDeviceIdentity).toMatch(/^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
    });
  });

  describe('logSuspiciousActivity', () => {
    it('should log suspicious activity with risk indicators', async () => {
      const event: SuspiciousActivityEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        activityType: 'BRUTE_FORCE',
        details: 'Multiple failed login attempts',
        riskIndicators: ['high_velocity', 'multiple_failures', 'unknown_device'],
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logSuspiciousActivity(event);

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO audit_logs'),
        expect.arrayContaining(['SUSPICIOUS_ACTIVITY', 'user-123', event.timestamp, false])
      );

      const callArgs = mockPoolQuery.mock.calls[0];
      const details = JSON.parse(callArgs[1][4]);
      expect(details.activityType).toBe('BRUTE_FORCE');
      expect(details.riskIndicators).toHaveLength(3);
    });
  });

  describe('logStepUpAttempt', () => {
    it('should log successful step-up attempt', async () => {
      const event: StepUpAttemptEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        method: VerificationMethod.EMAIL_OTP,
        success: true,
        sessionId: 'session-xyz',
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logStepUpAttempt(event);

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO audit_logs'),
        expect.arrayContaining(['STEP_UP_ATTEMPT', 'user-123', event.timestamp, true])
      );

      const callArgs = mockPoolQuery.mock.calls[0];
      const details = JSON.parse(callArgs[1][4]);
      expect(details.method).toBe(VerificationMethod.EMAIL_OTP);
      expect(details.sessionId).toBe('session-xyz');
    });

    it('should log failed step-up attempt', async () => {
      const event: StepUpAttemptEvent = {
        timestamp: new Date(),
        userId: 'user-123',
        method: VerificationMethod.SMS_OTP,
        success: false,
        sessionId: 'session-xyz',
      };

      mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

      await auditLogger.logStepUpAttempt(event);

      await new Promise(resolve => setTimeout(resolve, 100));

      const callArgs = mockPoolQuery.mock.calls[0];
      expect(callArgs[1][3]).toBe(false); // success = false
    });
  });

  describe('queryLogs', () => {
    it('should query logs for specific user with user isolation', async () => {
      const mockRows = [
        {
          id: '1',
          timestamp: new Date(),
          event_type: 'AUTH_ATTEMPT',
          user_id: 'user-123',
          success: true,
          details: JSON.stringify({ success: true }),
          encrypted_fields: [],
        },
      ];

      mockPoolQuery.mockResolvedValueOnce({ rows: mockRows });

      const logs = await auditLogger.queryLogs('user-123');

      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE user_id = $1'),
        ['user-123']
      );
      expect(logs).toHaveLength(1);
      expect(logs[0].userId).toBe('user-123');
    });

    it('should apply event type filter', async () => {
      mockPoolQuery.mockResolvedValueOnce({ rows: [] });

      await auditLogger.queryLogs('user-123', { eventType: 'AUTH_ATTEMPT' });

      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('AND event_type = $2'),
        ['user-123', 'AUTH_ATTEMPT']
      );
    });

    it('should apply date range filters', async () => {
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-12-31');

      mockPoolQuery.mockResolvedValueOnce({ rows: [] });

      await auditLogger.queryLogs('user-123', { startDate, endDate });

      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('AND timestamp >= $2'),
        expect.arrayContaining(['user-123', startDate, endDate])
      );
    });

    it('should apply pagination', async () => {
      mockPoolQuery.mockResolvedValueOnce({ rows: [] });

      await auditLogger.queryLogs('user-123', { limit: 10, offset: 20 });

      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('LIMIT $2'),
        expect.arrayContaining(['user-123', 10, 20])
      );
    });

    it('should decrypt sensitive fields when querying', async () => {
      // Create a real encrypted value
      const testLogger = new AuditLogger('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const encrypted = (testLogger as any).encrypt('192.168.1.1');

      const mockRows = [
        {
          id: '1',
          timestamp: new Date(),
          event_type: 'AUTH_ATTEMPT',
          user_id: 'user-123',
          success: true,
          details: JSON.stringify({ encryptedIpAddress: encrypted }),
          encrypted_fields: ['ipAddress'],
        },
      ];

      mockPoolQuery.mockResolvedValueOnce({ rows: mockRows });

      const logs = await testLogger.queryLogs('user-123');

      expect(logs[0].details.ipAddress).toBe('192.168.1.1');
      expect(logs[0].details.encryptedIpAddress).toBeUndefined();
    });
  });

  describe('enforceRetentionPolicy', () => {
    it('should delete logs older than retention period', async () => {
      mockPoolQuery.mockResolvedValue({ rows: [], rowCount: 0 });

      await auditLogger.enforceRetentionPolicy();

      // Should be called for each event type
      expect(mockPoolQuery).toHaveBeenCalledTimes(5);
      
      // Check AUTH_ATTEMPT retention (90 days)
      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM audit_logs'),
        expect.arrayContaining(['AUTH_ATTEMPT', expect.any(Date)])
      );

      // Check RISK_EVALUATION retention (30 days)
      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM audit_logs'),
        expect.arrayContaining(['RISK_EVALUATION', expect.any(Date)])
      );

      // Check DEVICE_CHANGE retention (365 days)
      expect(mockPoolQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM audit_logs'),
        expect.arrayContaining(['DEVICE_CHANGE', expect.any(Date)])
      );
    });
  });

  describe('Property-Based Tests', () => {
    /**
     * Feature: adaptive-risk-auth-engine, Property 34: Login attempt logging completeness
     * **Validates: Requirements 8.1**
     */
    it('Property 34: login attempt logs contain all required fields', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            userId: fc.uuid(),
            deviceIdentity: fc.hexaString({ minLength: 32, maxLength: 64 }),
            ipAddress: fc.ipV4(),
            success: fc.boolean(),
            failureReason: fc.option(fc.string(), { nil: undefined }),
          }),
          async (data) => {
            jest.clearAllMocks();
            mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

            const event: AuthAttemptEvent = {
              timestamp: new Date(),
              ...data,
            };

            await auditLogger.logAuthAttempt(event);
            await new Promise(resolve => setTimeout(resolve, 100));

            expect(mockPoolQuery).toHaveBeenCalled();
            const callArgs = mockPoolQuery.mock.calls[0];
            
            // Verify all required fields are present
            expect(callArgs[1][0]).toBe('AUTH_ATTEMPT'); // eventType
            expect(callArgs[1][1]).toBe(data.userId); // userId
            expect(callArgs[1][2]).toBeInstanceOf(Date); // timestamp
            expect(callArgs[1][3]).toBe(data.success); // success
            
            const details = JSON.parse(callArgs[1][4]);
            expect(details.encryptedIpAddress).toBeDefined();
            expect(details.encryptedDeviceIdentity).toBeDefined();
          }
        ),
        { numRuns: 20 }
      );
    }, 30000);

    /**
     * Feature: adaptive-risk-auth-engine, Property 35: Risk evaluation logging
     * **Validates: Requirements 8.2**
     */
    it('Property 35: risk evaluation logs contain score, factors, and trust level', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            userId: fc.uuid(),
            riskScore: fc.integer({ min: 0, max: 100 }),
            trustLevel: fc.constantFrom(
              SessionTrustLevel.FULL_TRUST,
              SessionTrustLevel.LIMITED_TRUST,
              SessionTrustLevel.UNVERIFIED,
              SessionTrustLevel.HIGH_RISK
            ),
            factors: fc.array(
              fc.record({
                name: fc.constantFrom('deviceFamiliarity', 'geographicAnomaly', 'ipReputation'),
                weight: fc.double({ min: 0, max: 1 }),
                contribution: fc.integer({ min: 0, max: 50 }),
                details: fc.string(),
              }),
              { minLength: 1, maxLength: 5 }
            ),
          }),
          async (data) => {
            jest.clearAllMocks();
            mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

            const event: RiskEvaluationEvent = {
              timestamp: new Date(),
              ...data,
            };

            await auditLogger.logRiskEvaluation(event);
            await new Promise(resolve => setTimeout(resolve, 100));

            expect(mockPoolQuery).toHaveBeenCalled();
            const callArgs = mockPoolQuery.mock.calls[0];
            const details = JSON.parse(callArgs[1][4]);

            expect(details.riskScore).toBe(data.riskScore);
            expect(details.trustLevel).toBe(data.trustLevel);
            expect(details.factors).toHaveLength(data.factors.length);
            if (details.factors.length > 0) {
              expect(details.factors[0]).toHaveProperty('name');
              expect(details.factors[0]).toHaveProperty('weight');
              expect(details.factors[0]).toHaveProperty('contribution');
              expect(details.factors[0]).toHaveProperty('details');
            }
          }
        ),
        { numRuns: 20 }
      );
    }, 30000);

    /**
     * Feature: adaptive-risk-auth-engine, Property 36: Device change logging
     * **Validates: Requirements 8.3**
     */
    it('Property 36: device change logs contain change details, timestamp, and user', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            userId: fc.uuid(),
            deviceIdentity: fc.hexaString({ minLength: 32, maxLength: 64 }),
            changeType: fc.constantFrom('TRUST', 'REVOKE', 'REGISTER'),
            oldStatus: fc.option(
              fc.constantFrom(TrustStatus.TRUSTED, TrustStatus.UNTRUSTED, TrustStatus.PENDING),
              { nil: undefined }
            ),
            newStatus: fc.option(
              fc.constantFrom(TrustStatus.TRUSTED, TrustStatus.UNTRUSTED, TrustStatus.PENDING),
              { nil: undefined }
            ),
          }),
          async (data) => {
            jest.clearAllMocks();
            mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

            const event: DeviceChangeEvent = {
              timestamp: new Date(),
              ...data,
            } as DeviceChangeEvent;

            await auditLogger.logDeviceChange(event);
            await new Promise(resolve => setTimeout(resolve, 100));

            expect(mockPoolQuery).toHaveBeenCalled();
            const callArgs = mockPoolQuery.mock.calls[0];
            
            expect(callArgs[1][0]).toBe('DEVICE_CHANGE');
            expect(callArgs[1][1]).toBe(data.userId);
            expect(callArgs[1][2]).toBeInstanceOf(Date);
            
            const details = JSON.parse(callArgs[1][4]);
            expect(details.changeType).toBe(data.changeType);
            expect(details.encryptedDeviceIdentity).toBeDefined();
          }
        ),
        { numRuns: 20 }
      );
    }, 30000);

    /**
     * Feature: adaptive-risk-auth-engine, Property 38: Step-up attempt logging
     * **Validates: Requirements 8.5**
     */
    it('Property 38: step-up logs contain method, outcome, and timestamp', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            userId: fc.uuid(),
            method: fc.constantFrom(
              VerificationMethod.EMAIL_OTP,
              VerificationMethod.SMS_OTP,
              VerificationMethod.AUTHENTICATOR_APP
            ),
            success: fc.boolean(),
            sessionId: fc.uuid(),
          }),
          async (data) => {
            jest.clearAllMocks();
            mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

            const event: StepUpAttemptEvent = {
              timestamp: new Date(),
              ...data,
            };

            await auditLogger.logStepUpAttempt(event);
            await new Promise(resolve => setTimeout(resolve, 100));

            expect(mockPoolQuery).toHaveBeenCalled();
            const callArgs = mockPoolQuery.mock.calls[0];
            
            expect(callArgs[1][0]).toBe('STEP_UP_ATTEMPT');
            expect(callArgs[1][2]).toBeInstanceOf(Date);
            expect(callArgs[1][3]).toBe(data.success);
            
            const details = JSON.parse(callArgs[1][4]);
            expect(details.method).toBe(data.method);
            expect(details.sessionId).toBe(data.sessionId);
          }
        ),
        { numRuns: 20 }
      );
    }, 30000);

    /**
     * Feature: adaptive-risk-auth-engine, Property 39: Sensitive data encryption
     * **Validates: Requirements 8.6, 9.7**
     */
    it('Property 39: sensitive data is encrypted before storage', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            userId: fc.uuid(),
            deviceIdentity: fc.hexaString({ minLength: 32, maxLength: 64 }),
            ipAddress: fc.ipV4(),
          }),
          async (data) => {
            jest.clearAllMocks();
            mockPoolQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

            const event: AuthAttemptEvent = {
              timestamp: new Date(),
              success: true,
              ...data,
            };

            await auditLogger.logAuthAttempt(event);
            await new Promise(resolve => setTimeout(resolve, 100));

            const callArgs = mockPoolQuery.mock.calls[0];
            const details = JSON.parse(callArgs[1][4]);
            
            // Encrypted data should not match original
            expect(details.encryptedIpAddress).not.toBe(data.ipAddress);
            expect(details.encryptedDeviceIdentity).not.toBe(data.deviceIdentity);
            
            // Encrypted data should have proper format
            expect(details.encryptedIpAddress).toMatch(/^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
            expect(details.encryptedDeviceIdentity).toMatch(/^[0-9a-f]+:[0-9a-f]+:[0-9a-f]+$/);
          }
        ),
        { numRuns: 20 }
      );
    }, 30000);

    /**
     * Feature: adaptive-risk-auth-engine, Property 48: User audit log access
     * **Validates: Requirements 12.3**
     */
    it('Property 48: queryLogs only returns logs for specified user', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.uuid(),
          fc.array(
            fc.record({
              id: fc.uuid(),
              user_id: fc.uuid(),
              event_type: fc.constantFrom('AUTH_ATTEMPT', 'RISK_EVALUATION', 'DEVICE_CHANGE'),
              timestamp: fc.date(),
              success: fc.boolean(),
              details: fc.constant('{}'),
              encrypted_fields: fc.constant([]),
            }),
            { minLength: 5, maxLength: 20 }
          ),
          async (targetUserId, allLogs) => {
            // Filter logs to only include target user's logs
            const userLogs = allLogs.filter(log => log.user_id === targetUserId);
            
            mockPoolQuery.mockResolvedValueOnce({ rows: userLogs });

            const result = await auditLogger.queryLogs(targetUserId);

            // Verify query includes user isolation
            expect(mockPoolQuery).toHaveBeenCalledWith(
              expect.stringContaining('WHERE user_id = $1'),
              expect.arrayContaining([targetUserId])
            );

            // All returned logs should belong to the target user
            result.forEach(log => {
              expect(log.userId).toBe(targetUserId);
            });
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
