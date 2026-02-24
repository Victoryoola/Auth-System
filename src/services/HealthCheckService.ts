import { pool } from '../config/database';
import { redisClient } from '../config/redis';

/**
 * Health check result
 */
export interface HealthCheckResult {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
  checks: {
    database: CheckStatus;
    cache: CheckStatus;
  };
}

/**
 * Individual check status
 */
interface CheckStatus {
  status: 'up' | 'down';
  message?: string;
  responseTime?: number;
}

/**
 * HealthCheckService - Provides health and readiness checks
 * 
 * - /health: Simple liveness check (returns 200 if service is running)
 * - /ready: Readiness check (verifies database and cache connectivity)
 */
export class HealthCheckService {
  /**
   * Simple liveness check
   * Returns true if the service is running
   */
  async checkLiveness(): Promise<boolean> {
    return true;
  }

  /**
   * Comprehensive readiness check
   * Verifies database and cache connectivity
   */
  async checkReadiness(): Promise<HealthCheckResult> {
    const timestamp = new Date().toISOString();
    
    // Check database connectivity
    const databaseCheck = await this.checkDatabase();
    
    // Check Redis cache connectivity
    const cacheCheck = await this.checkCache();
    
    // Determine overall status
    const status = 
      databaseCheck.status === 'up' && cacheCheck.status === 'up'
        ? 'healthy'
        : 'unhealthy';

    return {
      status,
      timestamp,
      checks: {
        database: databaseCheck,
        cache: cacheCheck,
      },
    };
  }

  /**
   * Check database connectivity
   */
  private async checkDatabase(): Promise<CheckStatus> {
    const startTime = Date.now();
    
    try {
      // Simple query to check database connectivity
      await pool.query('SELECT 1');
      const responseTime = Date.now() - startTime;
      
      return {
        status: 'up',
        responseTime,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const message = error instanceof Error ? error.message : 'Unknown error';
      
      return {
        status: 'down',
        message,
        responseTime,
      };
    }
  }

  /**
   * Check Redis cache connectivity
   */
  private async checkCache(): Promise<CheckStatus> {
    const startTime = Date.now();
    
    try {
      // Check if Redis client is connected
      if (!redisClient.isOpen) {
        return {
          status: 'down',
          message: 'Redis client not connected',
          responseTime: Date.now() - startTime,
        };
      }

      // Simple ping to check Redis connectivity
      await redisClient.ping();
      const responseTime = Date.now() - startTime;
      
      return {
        status: 'up',
        responseTime,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const message = error instanceof Error ? error.message : 'Unknown error';
      
      return {
        status: 'down',
        message,
        responseTime,
      };
    }
  }
}
