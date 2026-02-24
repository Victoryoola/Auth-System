import { Registry, Counter, Histogram, collectDefaultMetrics } from 'prom-client';

/**
 * MetricsService - Centralized metrics collection for monitoring and observability
 * 
 * Provides Prometheus-compatible metrics for:
 * - Authentication attempts (success/failure)
 * - Risk score distribution
 * - Session creation
 * - API endpoint latency
 * - API error rates
 * - Rate limiting triggers
 */
export class MetricsService {
  private registry: Registry;

  // Authentication metrics
  private authAttemptsCounter: Counter;
  private sessionCreationCounter: Counter;
  private riskScoreHistogram: Histogram;

  // API metrics
  private apiLatencyHistogram: Histogram;
  private apiErrorCounter: Counter;

  // Security metrics
  private rateLimitCounter: Counter;

  constructor() {
    this.registry = new Registry();

    // Collect default metrics (CPU, memory, etc.)
    collectDefaultMetrics({ register: this.registry });

    // Authentication attempts counter
    this.authAttemptsCounter = new Counter({
      name: 'auth_attempts_total',
      help: 'Total number of authentication attempts',
      labelNames: ['status', 'method'],
      registers: [this.registry],
    });

    // Session creation counter
    this.sessionCreationCounter = new Counter({
      name: 'sessions_created_total',
      help: 'Total number of sessions created',
      labelNames: ['trust_level'],
      registers: [this.registry],
    });

    // Risk score distribution histogram
    this.riskScoreHistogram = new Histogram({
      name: 'risk_score_distribution',
      help: 'Distribution of risk scores calculated',
      labelNames: ['trust_level'],
      buckets: [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
      registers: [this.registry],
    });

    // API endpoint latency histogram
    this.apiLatencyHistogram = new Histogram({
      name: 'api_request_duration_ms',
      help: 'API endpoint request duration in milliseconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [10, 50, 100, 200, 500, 1000, 2000, 5000],
      registers: [this.registry],
    });

    // API error counter
    this.apiErrorCounter = new Counter({
      name: 'api_errors_total',
      help: 'Total number of API errors',
      labelNames: ['method', 'route', 'status_code'],
      registers: [this.registry],
    });

    // Rate limiting counter
    this.rateLimitCounter = new Counter({
      name: 'rate_limit_triggers_total',
      help: 'Total number of rate limit triggers',
      labelNames: ['endpoint'],
      registers: [this.registry],
    });
  }

  /**
   * Record an authentication attempt
   * @param status - 'success' or 'failure'
   * @param method - Authentication method (e.g., 'password', 'mfa')
   */
  recordAuthAttempt(status: 'success' | 'failure', method: string = 'password'): void {
    this.authAttemptsCounter.inc({ status, method });
  }

  /**
   * Record a session creation
   * @param trustLevel - The trust level assigned to the session
   */
  recordSessionCreation(trustLevel: string): void {
    this.sessionCreationCounter.inc({ trust_level: trustLevel });
  }

  /**
   * Record a risk score calculation
   * @param score - The calculated risk score (0-100)
   * @param trustLevel - The assigned trust level
   */
  recordRiskScore(score: number, trustLevel: string): void {
    this.riskScoreHistogram.observe({ trust_level: trustLevel }, score);
  }

  /**
   * Record API request latency
   * @param method - HTTP method
   * @param route - API route
   * @param statusCode - HTTP status code
   * @param durationMs - Request duration in milliseconds
   */
  recordApiLatency(method: string, route: string, statusCode: number, durationMs: number): void {
    this.apiLatencyHistogram.observe(
      { method, route, status_code: statusCode.toString() },
      durationMs
    );
  }

  /**
   * Record an API error
   * @param method - HTTP method
   * @param route - API route
   * @param statusCode - HTTP status code
   */
  recordApiError(method: string, route: string, statusCode: number): void {
    this.apiErrorCounter.inc({ method, route, status_code: statusCode.toString() });
  }

  /**
   * Record a rate limit trigger
   * @param endpoint - The endpoint that triggered the rate limit
   */
  recordRateLimitTrigger(endpoint: string): void {
    this.rateLimitCounter.inc({ endpoint });
  }

  /**
   * Get metrics in Prometheus format
   * @returns Prometheus-formatted metrics string
   */
  async getMetrics(): Promise<string> {
    return this.registry.metrics();
  }

  /**
   * Get the registry instance (for testing or custom metrics)
   * @returns The Prometheus registry
   */
  getRegistry(): Registry {
    return this.registry;
  }
}
