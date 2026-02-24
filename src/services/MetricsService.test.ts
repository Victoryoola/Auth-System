import { MetricsService } from './MetricsService';

describe('MetricsService', () => {
  let metricsService: MetricsService;

  beforeEach(() => {
    metricsService = new MetricsService();
  });

  describe('recordAuthAttempt', () => {
    it('should record successful authentication attempt', () => {
      expect(() => {
        metricsService.recordAuthAttempt('success', 'password');
      }).not.toThrow();
    });

    it('should record failed authentication attempt', () => {
      expect(() => {
        metricsService.recordAuthAttempt('failure', 'password');
      }).not.toThrow();
    });

    it('should record MFA authentication attempt', () => {
      expect(() => {
        metricsService.recordAuthAttempt('success', 'mfa');
      }).not.toThrow();
    });
  });

  describe('recordSessionCreation', () => {
    it('should record session creation with trust level', () => {
      expect(() => {
        metricsService.recordSessionCreation('FULL_TRUST');
      }).not.toThrow();
    });
  });

  describe('recordRiskScore', () => {
    it('should record risk score with trust level', () => {
      expect(() => {
        metricsService.recordRiskScore(25, 'LIMITED_TRUST');
      }).not.toThrow();
    });

    it('should record high risk score', () => {
      expect(() => {
        metricsService.recordRiskScore(75, 'HIGH_RISK');
      }).not.toThrow();
    });
  });

  describe('recordApiLatency', () => {
    it('should record API request latency', () => {
      expect(() => {
        metricsService.recordApiLatency('POST', '/api/auth/login', 200, 150);
      }).not.toThrow();
    });

    it('should record slow API request', () => {
      expect(() => {
        metricsService.recordApiLatency('GET', '/api/devices', 200, 500);
      }).not.toThrow();
    });
  });

  describe('recordApiError', () => {
    it('should record 4xx error', () => {
      expect(() => {
        metricsService.recordApiError('POST', '/api/auth/login', 401);
      }).not.toThrow();
    });

    it('should record 5xx error', () => {
      expect(() => {
        metricsService.recordApiError('GET', '/api/sessions', 500);
      }).not.toThrow();
    });
  });

  describe('recordRateLimitTrigger', () => {
    it('should record rate limit trigger', () => {
      expect(() => {
        metricsService.recordRateLimitTrigger('/api/auth');
      }).not.toThrow();
    });
  });

  describe('getMetrics', () => {
    it('should return Prometheus-formatted metrics', async () => {
      // Record some metrics
      metricsService.recordAuthAttempt('success', 'password');
      metricsService.recordSessionCreation('FULL_TRUST');
      metricsService.recordRiskScore(15, 'FULL_TRUST');
      metricsService.recordApiLatency('POST', '/api/auth/login', 200, 120);

      const metrics = await metricsService.getMetrics();

      expect(metrics).toBeDefined();
      expect(typeof metrics).toBe('string');
      expect(metrics.length).toBeGreaterThan(0);
      
      // Check for expected metric names
      expect(metrics).toContain('auth_attempts_total');
      expect(metrics).toContain('sessions_created_total');
      expect(metrics).toContain('risk_score_distribution');
      expect(metrics).toContain('api_request_duration_ms');
    });

    it('should include default metrics', async () => {
      const metrics = await metricsService.getMetrics();

      // Default metrics should include process metrics
      expect(metrics).toContain('process_cpu');
      expect(metrics).toContain('nodejs_');
    });
  });

  describe('getRegistry', () => {
    it('should return the Prometheus registry', () => {
      const registry = metricsService.getRegistry();
      expect(registry).toBeDefined();
    });
  });
});
