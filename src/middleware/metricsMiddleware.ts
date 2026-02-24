import { Request, Response, NextFunction } from 'express';
import { MetricsService } from '../services/MetricsService';

/**
 * Middleware to automatically track API request metrics
 * Records latency and error rates for all API endpoints
 */
export function createMetricsMiddleware(metricsService: MetricsService) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const startTime = Date.now();

    // Capture the original end function
    const originalEnd = res.end.bind(res);

    // Override the end function to capture metrics
    res.end = function (chunk?: any, encoding?: any, callback?: any): Response {
      const durationMs = Date.now() - startTime;
      const statusCode = res.statusCode;
      const method = req.method;
      const route = req.route?.path || req.path;

      // Record latency
      metricsService.recordApiLatency(method, route, statusCode, durationMs);

      // Record errors (4xx and 5xx status codes)
      if (statusCode >= 400) {
        metricsService.recordApiError(method, route, statusCode);
      }

      // Call the original end function
      return originalEnd(chunk, encoding, callback);
    };

    next();
  };
}
