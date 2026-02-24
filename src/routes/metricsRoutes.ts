import { Router, Request, Response } from 'express';
import { MetricsService } from '../services/MetricsService';

/**
 * Create metrics routes for Prometheus scraping
 */
export function createMetricsRoutes(metricsService: MetricsService): Router {
  const router = Router();

  /**
   * GET /metrics
   * Returns Prometheus-formatted metrics for scraping
   */
  router.get('/', async (_req: Request, res: Response) => {
    try {
      const metrics = await metricsService.getMetrics();
      res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.send(metrics);
    } catch (error) {
      res.status(500).json({
        error: 'metrics_error',
        message: 'Failed to retrieve metrics',
      });
    }
  });

  return router;
}
