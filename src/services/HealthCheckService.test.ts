import { HealthCheckService } from './HealthCheckService';

describe('HealthCheckService', () => {
  let healthCheckService: HealthCheckService;

  beforeEach(() => {
    healthCheckService = new HealthCheckService();
  });

  describe('checkLiveness', () => {
    it('should return true indicating service is alive', async () => {
      const result = await healthCheckService.checkLiveness();
      expect(result).toBe(true);
    });
  });

  describe('checkReadiness', () => {
    it('should return health check result with status', async () => {
      const result = await healthCheckService.checkReadiness();

      expect(result).toBeDefined();
      expect(result.status).toBeDefined();
      expect(['healthy', 'unhealthy']).toContain(result.status);
      expect(result.timestamp).toBeDefined();
      expect(result.checks).toBeDefined();
      expect(result.checks.database).toBeDefined();
      expect(result.checks.cache).toBeDefined();
    });

    it('should check database connectivity', async () => {
      const result = await healthCheckService.checkReadiness();

      expect(result.checks.database.status).toBeDefined();
      expect(['up', 'down']).toContain(result.checks.database.status);
      
      if (result.checks.database.status === 'up') {
        expect(result.checks.database.responseTime).toBeDefined();
        expect(result.checks.database.responseTime).toBeGreaterThanOrEqual(0);
      }
    });

    it('should check cache connectivity', async () => {
      const result = await healthCheckService.checkReadiness();

      expect(result.checks.cache.status).toBeDefined();
      expect(['up', 'down']).toContain(result.checks.cache.status);
      
      // In test environment, Redis might not be connected
      if (result.checks.cache.status === 'down') {
        expect(result.checks.cache.message).toBeDefined();
      }
    });

    it('should return unhealthy if any check fails', async () => {
      const result = await healthCheckService.checkReadiness();

      if (result.checks.database.status === 'down' || result.checks.cache.status === 'down') {
        expect(result.status).toBe('unhealthy');
      }
    });

    it('should return healthy if all checks pass', async () => {
      const result = await healthCheckService.checkReadiness();

      if (result.checks.database.status === 'up' && result.checks.cache.status === 'up') {
        expect(result.status).toBe('healthy');
      }
    });

    it('should include response times for checks', async () => {
      const result = await healthCheckService.checkReadiness();

      if (result.checks.database.status === 'up') {
        expect(result.checks.database.responseTime).toBeGreaterThanOrEqual(0);
      }

      if (result.checks.cache.status === 'up') {
        expect(result.checks.cache.responseTime).toBeGreaterThanOrEqual(0);
      }
    });
  });
});
