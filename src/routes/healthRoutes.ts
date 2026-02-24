import { Router, Request, Response } from 'express';
import { HealthCheckService } from '../services/HealthCheckService';

/**
 * Create health check routes
 */
export function createHealthRoutes(healthCheckService: HealthCheckService): Router {
  const router = Router();

  /**
   * GET /health
   * Simple liveness check - returns 200 if service is running
   */
  router.get('/health', async (_req: Request, res: Response) => {
    try {
      const isAlive = await healthCheckService.checkLiveness();
      
      if (isAlive) {
        res.status(200).json({
          status: 'ok',
          timestamp: new Date().toISOString(),
        });
      } else {
        res.status(503).json({
          status: 'error',
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      res.status(503).json({
        status: 'error',
        timestamp: new Date().toISOString(),
        message: 'Health check failed',
      });
    }
  });

  /**
   * GET /ready
   * Readiness check - verifies database and cache connectivity
   */
  router.get('/ready', async (_req: Request, res: Response) => {
    try {
      const result = await healthCheckService.checkReadiness();
      
      if (result.status === 'healthy') {
        res.status(200).json(result);
      } else {
        res.status(503).json(result);
      }
    } catch (error) {
      res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        message: 'Readiness check failed',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  return router;
}
