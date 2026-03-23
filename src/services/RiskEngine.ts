import { pool } from '../config/database';
import { SessionTrustLevel } from '../types/enums';
import { DeviceRegistry } from './DeviceRegistry';
import { MetricsService } from './MetricsService';

/**
 * Authentication context for risk evaluation
 */
export interface AuthContext {
  userId: string;
  deviceIdentity: string;
  ipAddress: string;
  timestamp: Date;
  failedAttempts: number;
}

/**
 * Risk factor details
 */
export interface RiskFactor {
  name: string;
  weight: number;
  contribution: number;
  details: string;
}

/**
 * Risk score result
 */
export interface RiskScore {
  score: number; // 0-100, higher = more risky
  factors: RiskFactor[];
  trustLevel: SessionTrustLevel;
}

/**
 * IP geolocation result
 */
interface GeolocationResult {
  country: string;
  isHighRisk: boolean;
}

/**
 * IP reputation result
 */
interface IPReputationResult {
  isProxy: boolean;
  isMalicious: boolean;
}

/**
 * Risk Engine service for calculating authentication risk scores
 */
export class RiskEngine {
  private deviceRegistry: DeviceRegistry;
  private metricsService?: MetricsService;
  private ipReputationCache: Map<string, { result: IPReputationResult; timestamp: number }>;
  private readonly IP_CACHE_TTL = 3600000; // 1 hour in milliseconds

  constructor(deviceRegistry: DeviceRegistry, metricsService?: MetricsService) {
    this.deviceRegistry = deviceRegistry;
    this.metricsService = metricsService;
    this.ipReputationCache = new Map();
  }

  /**
   * Calculate risk score for an authentication attempt
   */
  async calculateRiskScore(context: AuthContext): Promise<RiskScore> {
    const startTime = Date.now();

    // Evaluate all risk factors in parallel for performance
    const [
      deviceFamiliarityScore,
      geographicAnomalyScore,
      ipReputationScore,
      loginVelocityScore,
    ] = await Promise.all([
      this.evaluateDeviceFamiliarity(context.deviceIdentity, context.userId),
      this.evaluateGeographicAnomaly(context.ipAddress, context.userId),
      this.evaluateIPReputation(context.ipAddress),
      this.evaluateLoginVelocity(context.userId),
    ]);

    // Evaluate failed attempts (synchronous)
    const failedAttemptsScore = this.evaluateFailedAttempts(context.failedAttempts);

    // Calculate total trust score (higher = more trusted, max 100)
    const totalScore =
      deviceFamiliarityScore +
      geographicAnomalyScore +
      ipReputationScore +
      loginVelocityScore +
      failedAttemptsScore;

    // Assign trust level based on score
    const trustLevel = this.assignTrustLevel(totalScore);

    // Build risk factors array
    const factors: RiskFactor[] = [
      {
        name: 'Device Familiarity',
        weight: deviceFamiliarityScore,
        contribution: deviceFamiliarityScore,
        details: this.getDeviceFamiliarityDetails(deviceFamiliarityScore),
      },
      {
        name: 'Geographic Anomaly',
        weight: geographicAnomalyScore,
        contribution: geographicAnomalyScore,
        details: this.getGeographicAnomalyDetails(geographicAnomalyScore),
      },
      {
        name: 'IP Reputation',
        weight: ipReputationScore,
        contribution: ipReputationScore,
        details: this.getIPReputationDetails(ipReputationScore),
      },
      {
        name: 'Login Velocity',
        weight: loginVelocityScore,
        contribution: loginVelocityScore,
        details: this.getLoginVelocityDetails(loginVelocityScore),
      },
      {
        name: 'Failed Attempts',
        weight: failedAttemptsScore,
        contribution: failedAttemptsScore,
        details: this.getFailedAttemptsDetails(failedAttemptsScore),
      },
    ];

    const elapsedTime = Date.now() - startTime;
    if (elapsedTime > 200) {
      console.warn(`Risk evaluation took ${elapsedTime}ms, exceeding 200ms target`);
    }

    // Record trust score metrics
    this.metricsService?.recordRiskScore(totalScore, trustLevel);

    return {
      score: totalScore,
      factors,
      trustLevel,
    };
  }

  /**
   * Evaluate device familiarity trust factor
   * - Trusted device: +40
   * - Known but not trusted: +20
   * - Unknown device: +0
   */
  async evaluateDeviceFamiliarity(deviceIdentity: string, userId: string): Promise<number> {
    try {
      const isTrusted = await this.deviceRegistry.isDeviceTrusted(deviceIdentity, userId);
      
      if (isTrusted) {
        return 40; // Trusted device
      }

      // Check if device is known (exists for this user)
      const device = await this.deviceRegistry.getDevice(deviceIdentity);
      if (device && device.userId === userId) {
        return 20; // Known but not trusted
      }

      return 0; // Unknown device
    } catch (error) {
      console.error('Error evaluating device familiarity:', error);
      return 20; // Conservative default: treat as known but not trusted
    }
  }

  /**
   * Evaluate geographic anomaly trust factor
   * - Same country as usual: +30
   * - Different country: +10
   * - High-risk country: +0
   */
  async evaluateGeographicAnomaly(ipAddress: string, userId: string): Promise<number> {
    try {
      // Get geolocation for current IP
      const currentLocation = await this.getGeolocation(ipAddress);

      // Get user's typical location from recent logins
      const typicalCountry = await this.getUserTypicalCountry(userId);

      // If no history, treat as normal (first login or no data)
      if (!typicalCountry) {
        return currentLocation.isHighRisk ? 0 : 30;
      }

      // Check if high-risk country
      if (currentLocation.isHighRisk) {
        return 0;
      }

      // Check if different country
      if (currentLocation.country !== typicalCountry) {
        return 10;
      }

      return 30; // Same country as usual
    } catch (error) {
      console.error('Error evaluating geographic anomaly:', error);
      return 30; // Fail open: don't penalize if geolocation fails
    }
  }

  /**
   * Evaluate IP reputation trust factor
   * - Clean IP: +20
   * - Proxy/VPN: +10
   * - Known malicious: +0
   */
  async evaluateIPReputation(ipAddress: string): Promise<number> {
    try {
      // Check cache first
      const cached = this.ipReputationCache.get(ipAddress);
      if (cached && Date.now() - cached.timestamp < this.IP_CACHE_TTL) {
        return this.calculateIPReputationScore(cached.result);
      }

      // Fetch IP reputation
      const reputation = await this.fetchIPReputation(ipAddress);

      // Cache the result
      this.ipReputationCache.set(ipAddress, {
        result: reputation,
        timestamp: Date.now(),
      });

      return this.calculateIPReputationScore(reputation);
    } catch (error) {
      console.error('Error evaluating IP reputation:', error);
      return 0; // Fail open: don't penalize if reputation check fails
    }
  }

  /**
   * Evaluate login velocity trust factor
   * - Normal pattern: +10
   * - Multiple logins in 5 min: +5
   * - Multiple logins in 1 min: +0
   */
  async evaluateLoginVelocity(userId: string): Promise<number> {
    try {
      const now = Date.now();
      const oneMinuteAgo = new Date(now - 60000);
      const fiveMinutesAgo = new Date(now - 300000);

      // Count recent login attempts
      const result = await pool.query(
        `SELECT 
          COUNT(*) FILTER (WHERE timestamp > $1) as count_1min,
          COUNT(*) FILTER (WHERE timestamp > $2) as count_5min
         FROM risk_evaluations
         WHERE user_id = $3`,
        [oneMinuteAgo, fiveMinutesAgo, userId]
      );

      const count1min = parseInt(result.rows[0]?.count_1min || '0', 10);
      const count5min = parseInt(result.rows[0]?.count_5min || '0', 10);

      // Multiple logins in 1 minute
      if (count1min >= 2) {
        return 0;
      }

      // Multiple logins in 5 minutes
      if (count5min >= 2) {
        return 5;
      }

      return 10; // Normal pattern
    } catch (error) {
      console.error('Error evaluating login velocity:', error);
      return 10; // Fail open: don't penalize if velocity check fails
    }
  }

  /**
   * Evaluate failed attempts trust factor
   * - 0 recent failures: +0 penalty (full score)
   * - 1-2 failures: -5
   * - 3-5 failures: -10
   * - 6+ failures: -20
   */
  private evaluateFailedAttempts(failedAttempts: number): number {
    if (failedAttempts === 0) {
      return 0;
    } else if (failedAttempts <= 2) {
      return -5;
    } else if (failedAttempts <= 5) {
      return -10;
    } else {
      return -20;
    }
  }

  /**
   * Assign trust level based on trust score (higher = more trusted, max 100)
   * - Score 80–100: FULL_TRUST
   * - Score 60–79:  LIMITED_TRUST
   * - Score 40–59:  UNVERIFIED
   * - Score <40:    HIGH_RISK
   */
  private assignTrustLevel(score: number): SessionTrustLevel {
    if (score >= 80) {
      return SessionTrustLevel.FULL_TRUST;
    } else if (score >= 60) {
      return SessionTrustLevel.LIMITED_TRUST;
    } else if (score >= 40) {
      return SessionTrustLevel.UNVERIFIED;
    } else {
      return SessionTrustLevel.HIGH_RISK;
    }
  }

  /**
   * Get geolocation for an IP address
   */
  private async getGeolocation(ipAddress: string): Promise<GeolocationResult> {
    // For localhost/private IPs, return default
    if (this.isPrivateIP(ipAddress)) {
      return { country: 'US', isHighRisk: false };
    }

    // TODO: Integrate with actual geolocation service (e.g., MaxMind, IP2Location)
    // For now, return mock data
    return { country: 'US', isHighRisk: false };
  }

  /**
   * Get user's typical country from login history
   */
  private async getUserTypicalCountry(userId: string): Promise<string | null> {
    try {
      // Get the most common country from recent risk evaluations
      const result = await pool.query(
        `SELECT ip_address, COUNT(*) as count
         FROM risk_evaluations
         WHERE user_id = $1
           AND timestamp > NOW() - INTERVAL '30 days'
         GROUP BY ip_address
         ORDER BY count DESC
         LIMIT 1`,
        [userId]
      );

      if (result.rows.length === 0) {
        return null;
      }

      // Get geolocation for the most common IP
      const mostCommonIP = result.rows[0].ip_address;
      const location = await this.getGeolocation(mostCommonIP);
      return location.country;
    } catch (error) {
      console.error('Error getting user typical country:', error);
      return null;
    }
  }

  /**
   * Fetch IP reputation from external service
   */
  private async fetchIPReputation(ipAddress: string): Promise<IPReputationResult> {
    // For localhost/private IPs, return clean
    if (this.isPrivateIP(ipAddress)) {
      return { isProxy: false, isMalicious: false };
    }

    // TODO: Integrate with actual IP reputation service (e.g., AbuseIPDB, IPQualityScore)
    // For now, return mock data
    return { isProxy: false, isMalicious: false };
  }

  /**
   * Calculate IP reputation score from reputation result
   */
  private calculateIPReputationScore(reputation: IPReputationResult): number {
    if (reputation.isMalicious) {
      return 0;
    } else if (reputation.isProxy) {
      return 10;
    } else {
      return 20;
    }
  }

  /**
   * Check if IP address is private/localhost
   */
  private isPrivateIP(ipAddress: string): boolean {
    // Handle undefined or null
    if (!ipAddress) {
      return true; // Treat as private to avoid external lookups
    }

    // Check for localhost
    if (ipAddress === '127.0.0.1' || ipAddress === '::1' || ipAddress === 'localhost') {
      return true;
    }

    // Check for private IPv4 ranges
    const ipv4Regex = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    const match = ipAddress.match(ipv4Regex);
    if (match) {
      const [, a, b] = match.map(Number);
      return (
        a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168)
      );
    }

    return false;
  }

  // Helper methods for risk factor details
  private getDeviceFamiliarityDetails(score: number): string {
    if (score === 40) return 'Trusted device';
    if (score === 20) return 'Known but not trusted device';
    return 'Unknown device';
  }

  private getGeographicAnomalyDetails(score: number): string {
    if (score === 30) return 'Same country as usual';
    if (score === 10) return 'Different country';
    return 'High-risk country';
  }

  private getIPReputationDetails(score: number): string {
    if (score === 20) return 'Clean IP';
    if (score === 10) return 'Proxy/VPN detected';
    return 'Known malicious IP';
  }

  private getLoginVelocityDetails(score: number): string {
    if (score === 10) return 'Normal login pattern';
    if (score === 5) return 'Multiple logins in 5 minutes';
    return 'Multiple logins in 1 minute';
  }

  private getFailedAttemptsDetails(score: number): string {
    if (score === 0) return 'No recent failures';
    if (score === -5) return '1-2 recent failures';
    if (score === -10) return '3-5 recent failures';
    return '6+ recent failures';
  }
}
