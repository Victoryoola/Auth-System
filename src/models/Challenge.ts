import { VerificationMethod } from '../types/enums';

/**
 * Challenge model for step-up authentication
 */
export interface Challenge {
  id: string;
  userId: string;
  sessionId: string;
  method: VerificationMethod;
  otpHash?: string;
  createdAt: Date;
  expiresAt: Date;
  attemptsRemaining: number;
  verified: boolean;
}

/**
 * Challenge creation input
 */
export interface CreateChallengeInput {
  userId: string;
  sessionId: string;
  method: VerificationMethod;
  otpHash?: string;
  expiresAt: Date;
  attemptsRemaining?: number;
}

/**
 * Challenge update input
 */
export interface UpdateChallengeInput {
  attemptsRemaining?: number;
  verified?: boolean;
}
