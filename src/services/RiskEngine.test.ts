import { RiskEngine, AuthContext } from './RiskEngine';
import { DeviceRegistry } from './DeviceRegistry';
import { SessionTrustLevel } from '../types/enums';
import { pool } from '../config/database';

// Mock the database pool
jest.mock('../config/database', () => ({
  pool: {
    query: jest.fn(),
  },
}));

describe('RiskEngine', () => {
  let riskEngine: RiskEngine;
  let deviceRegistry: DeviceRegistry;

  beforeEach(() => {
    deviceRegistry = new DeviceRegistry();
    riskEngine = new RiskEngine(deviceRegistry);
    jest.clearAllMocks();
  });

  describe('calculateRiskScore', () => {
    it('should calculate risk score for trusted device with no anomalies', async () => {
      const context: AuthContext = {
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        ipAddress: '192.168.1.1',
        timestamp: new Date(),
        failedAttempts: 0,
      };

      // Mock device as trusted
      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(true);

      // Mock no recent logins (normal velocity)
      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ count_1min: '0', count_5min: '0' }],
      });

      // Mock typical country lookup (no history)
      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [],
      });

      const result = await riskEngine.calculateRiskScore(context);

      expect(result.score).toBe(0); // All factors should be 0
      expect(result.trustLevel).toBe(SessionTrustLevel.FULL_TRUST);
      expect(result.factors).toHaveLength(5);
    });

    it('should calculate high risk score for unknown device with failures', async () => {
      const context: AuthContext = {
        userId: 'user-123',
        deviceIdentity: 'unknown-device',
        ipAddress: '192.168.1.1',
        timestamp: new Date(),
        failedAttempts: 6,
      };

      // Mock device as unknown
      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(false);
      jest.spyOn(deviceRegistry, 'getDevice').mockResolvedValue(null);

      // Mock no recent logins
      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ count_1min: '0', count_5min: '0' }],
      });

      // Mock typical country lookup
      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [],
      });

      const result = await riskEngine.calculateRiskScore(context);

      // Unknown device (30) + 6+ failures (40) = 70
      expect(result.score).toBe(70);
      expect(result.trustLevel).toBe(SessionTrustLevel.HIGH_RISK);
    });

    it('should complete risk evaluation within 200ms', async () => {
      const context: AuthContext = {
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        ipAddress: '192.168.1.1',
        timestamp: new Date(),
        failedAttempts: 0,
      };

      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(true);
      (pool.query as jest.Mock).mockResolvedValue({
        rows: [{ count_1min: '0', count_5min: '0' }],
      });

      const startTime = Date.now();
      await riskEngine.calculateRiskScore(context);
      const elapsedTime = Date.now() - startTime;

      expect(elapsedTime).toBeLessThan(200);
    });
  });

  describe('evaluateDeviceFamiliarity', () => {
    it('should return 0 for trusted device', async () => {
      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(true);

      const score = await riskEngine.evaluateDeviceFamiliarity('device-123', 'user-123');

      expect(score).toBe(0);
    });

    it('should return 15 for known but untrusted device', async () => {
      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(false);
      jest.spyOn(deviceRegistry, 'getDevice').mockResolvedValue({
        id: 'device-id',
        userId: 'user-123',
        identity: 'device-123',
        trustStatus: 'UNTRUSTED' as any,
        revoked: false,
        firstSeen: new Date(),
        lastSeen: new Date(),
        metadata: {
          deviceType: 'desktop',
          browser: 'Chrome',
          operatingSystem: 'Windows',
          lastIpAddress: '192.168.1.1',
        },
      });

      const score = await riskEngine.evaluateDeviceFamiliarity('device-123', 'user-123');

      expect(score).toBe(15);
    });

    it('should return 30 for unknown device', async () => {
      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(false);
      jest.spyOn(deviceRegistry, 'getDevice').mockResolvedValue(null);

      const score = await riskEngine.evaluateDeviceFamiliarity('unknown-device', 'user-123');

      expect(score).toBe(30);
    });
  });

  describe('evaluateGeographicAnomaly', () => {
    it('should return 0 for same country as usual', async () => {
      // Mock typical country lookup
      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ ip_address: '192.168.1.1', count: '10' }],
      });

      const score = await riskEngine.evaluateGeographicAnomaly('192.168.1.1', 'user-123');

      expect(score).toBe(0);
    });

    it('should return 0 for first login (no history)', async () => {
      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [],
      });

      const score = await riskEngine.evaluateGeographicAnomaly('192.168.1.1', 'user-123');

      expect(score).toBe(0);
    });
  });

  describe('evaluateIPReputation', () => {
    it('should return 0 for clean IP', async () => {
      const score = await riskEngine.evaluateIPReputation('192.168.1.1');

      expect(score).toBe(0);
    });

    it('should cache IP reputation results', async () => {
      const ip = '8.8.8.8';

      // First call
      const score1 = await riskEngine.evaluateIPReputation(ip);
      // Second call (should use cache)
      const score2 = await riskEngine.evaluateIPReputation(ip);

      expect(score1).toBe(score2);
    });
  });

  describe('evaluateLoginVelocity', () => {
    it('should return 0 for normal login pattern', async () => {
      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ count_1min: '0', count_5min: '0' }],
      });

      const score = await riskEngine.evaluateLoginVelocity('user-123');

      expect(score).toBe(0);
    });

    it('should return 15 for multiple logins in 5 minutes', async () => {
      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ count_1min: '1', count_5min: '2' }],
      });

      const score = await riskEngine.evaluateLoginVelocity('user-123');

      expect(score).toBe(15);
    });

    it('should return 30 for multiple logins in 1 minute', async () => {
      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [{ count_1min: '2', count_5min: '3' }],
      });

      const score = await riskEngine.evaluateLoginVelocity('user-123');

      expect(score).toBe(30);
    });
  });

  describe('assignTrustLevel', () => {
    it('should assign FULL_TRUST for score 0-20', async () => {
      const context: AuthContext = {
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        ipAddress: '192.168.1.1',
        timestamp: new Date(),
        failedAttempts: 0,
      };

      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(true);
      (pool.query as jest.Mock).mockResolvedValue({
        rows: [{ count_1min: '0', count_5min: '0' }],
      });

      const result = await riskEngine.calculateRiskScore(context);

      expect(result.trustLevel).toBe(SessionTrustLevel.FULL_TRUST);
    });

    it('should assign LIMITED_TRUST for score 21-40', async () => {
      const context: AuthContext = {
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        ipAddress: '192.168.1.1',
        timestamp: new Date(),
        failedAttempts: 2, // +10
      };

      // Known but not trusted device (+15)
      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(false);
      jest.spyOn(deviceRegistry, 'getDevice').mockResolvedValue({
        id: 'device-id',
        userId: 'user-123',
        identity: 'device-abc',
        trustStatus: 'UNTRUSTED' as any,
        revoked: false,
        firstSeen: new Date(),
        lastSeen: new Date(),
        metadata: {
          deviceType: 'desktop',
          browser: 'Chrome',
          operatingSystem: 'Windows',
          lastIpAddress: '192.168.1.1',
        },
      });

      (pool.query as jest.Mock).mockResolvedValue({
        rows: [{ count_1min: '0', count_5min: '0' }],
      });

      const result = await riskEngine.calculateRiskScore(context);

      expect(result.score).toBe(25); // 15 + 10
      expect(result.trustLevel).toBe(SessionTrustLevel.LIMITED_TRUST);
    });

    it('should assign UNVERIFIED for score 41-60', async () => {
      const context: AuthContext = {
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        ipAddress: '192.168.1.1',
        timestamp: new Date(),
        failedAttempts: 4, // +25
      };

      // Unknown device (+30)
      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(false);
      jest.spyOn(deviceRegistry, 'getDevice').mockResolvedValue(null);

      (pool.query as jest.Mock).mockResolvedValue({
        rows: [{ count_1min: '0', count_5min: '0' }],
      });

      const result = await riskEngine.calculateRiskScore(context);

      expect(result.score).toBe(55); // 30 + 25
      expect(result.trustLevel).toBe(SessionTrustLevel.UNVERIFIED);
    });

    it('should assign HIGH_RISK for score 61+', async () => {
      const context: AuthContext = {
        userId: 'user-123',
        deviceIdentity: 'device-abc',
        ipAddress: '192.168.1.1',
        timestamp: new Date(),
        failedAttempts: 6, // +40
      };

      // Unknown device (+30)
      jest.spyOn(deviceRegistry, 'isDeviceTrusted').mockResolvedValue(false);
      jest.spyOn(deviceRegistry, 'getDevice').mockResolvedValue(null);

      (pool.query as jest.Mock).mockResolvedValue({
        rows: [{ count_1min: '0', count_5min: '0' }],
      });

      const result = await riskEngine.calculateRiskScore(context);

      expect(result.score).toBe(70); // 30 + 40
      expect(result.trustLevel).toBe(SessionTrustLevel.HIGH_RISK);
    });
  });
});
