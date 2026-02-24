import { SessionTrustLevel, VerificationMethod, TrustStatus } from './enums';

/**
 * Risk factor from risk evaluation
 */
export interface RiskFactor {
  name: string;
  weight: number;
  contribution: number;
  details: string;
}

/**
 * Authentication attempt event
 */
export interface AuthAttemptEvent {
  timestamp: Date;
  userId: string;
  deviceIdentity: string;
  ipAddress: string;
  success: boolean;
  failureReason?: string;
}

/**
 * Risk evaluation event
 */
export interface RiskEvaluationEvent {
  timestamp: Date;
  userId: string;
  riskScore: number;
  factors: RiskFactor[];
  trustLevel: SessionTrustLevel;
}

/**
 * Device change event
 */
export interface DeviceChangeEvent {
  timestamp: Date;
  userId: string;
  deviceIdentity: string;
  changeType: 'TRUST' | 'REVOKE' | 'REGISTER';
  oldStatus?: TrustStatus;
  newStatus?: TrustStatus;
}

/**
 * Suspicious activity event
 */
export interface SuspiciousActivityEvent {
  timestamp: Date;
  userId: string;
  activityType: string;
  details: string;
  riskIndicators: string[];
}

/**
 * Step-up authentication attempt event
 */
export interface StepUpAttemptEvent {
  timestamp: Date;
  userId: string;
  method: VerificationMethod;
  success: boolean;
  sessionId: string;
}

/**
 * Log filters for querying audit logs
 */
export interface LogFilters {
  eventType?: string;
  startDate?: Date;
  endDate?: Date;
  success?: boolean;
  limit?: number;
  offset?: number;
}
