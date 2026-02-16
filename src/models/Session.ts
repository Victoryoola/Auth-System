import { SessionTrustLevel } from '../types/enums';

/**
 * Session model representing active user sessions
 */
export interface Session {
  id: string;
  userId: string;
  trustLevel: SessionTrustLevel;
  deviceIdentity: string;
  accessTokenHash: string;
  refreshTokenHash: string;
  refreshTokenFamily: string;
  accessTokenExpiry: Date;
  refreshTokenExpiry: Date;
  createdAt: Date;
  lastActivity: Date;
  ipAddress: string;
  revoked: boolean;
}

/**
 * Session creation input
 */
export interface CreateSessionInput {
  userId: string;
  trustLevel: SessionTrustLevel;
  deviceIdentity: string;
  accessTokenHash: string;
  refreshTokenHash: string;
  refreshTokenFamily: string;
  accessTokenExpiry: Date;
  refreshTokenExpiry: Date;
  ipAddress: string;
}

/**
 * Session update input
 */
export interface UpdateSessionInput {
  trustLevel?: SessionTrustLevel;
  accessTokenHash?: string;
  refreshTokenHash?: string;
  accessTokenExpiry?: Date;
  refreshTokenExpiry?: Date;
  lastActivity?: Date;
  revoked?: boolean;
}
