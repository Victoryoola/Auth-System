import { SessionTrustLevel } from '../types/enums';

/**
 * Risk factors contributing to the overall risk score
 */
export interface RiskFactors {
  deviceFamiliarity: number;
  geographicAnomaly: number;
  ipReputation: number;
  loginVelocity: number;
  failedAttempts: number;
}

/**
 * Risk evaluation model storing risk assessment results
 */
export interface RiskEvaluation {
  id: string;
  userId: string;
  deviceIdentity: string;
  ipAddress: string;
  timestamp: Date;
  riskScore: number;
  trustLevel: SessionTrustLevel;
  factors: RiskFactors;
}

/**
 * Risk evaluation creation input
 */
export interface CreateRiskEvaluationInput {
  userId: string;
  deviceIdentity: string;
  ipAddress: string;
  riskScore: number;
  trustLevel: SessionTrustLevel;
  factors: RiskFactors;
}
