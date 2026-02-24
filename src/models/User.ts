/**
 * User model representing authenticated users in the system
 */
export interface User {
  id: string;
  email: string;
  passwordHash: string;
  mfaEnabled: boolean;
  mfaSecret?: string;
  deviceTrackingEnabled: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date;
  failedLoginAttempts: number;
  lastFailedLoginAt?: Date;
  accountLocked: boolean;
  lockoutUntil?: Date;
}

/**
 * User creation input (without generated fields)
 */
export interface CreateUserInput {
  email: string;
  passwordHash: string;
  mfaEnabled?: boolean;
  mfaSecret?: string;
  deviceTrackingEnabled?: boolean;
}

/**
 * User update input (partial fields)
 */
export interface UpdateUserInput {
  email?: string;
  passwordHash?: string;
  mfaEnabled?: boolean;
  mfaSecret?: string;
  deviceTrackingEnabled?: boolean;
  lastLoginAt?: Date;
  failedLoginAttempts?: number;
  lastFailedLoginAt?: Date;
  accountLocked?: boolean;
  lockoutUntil?: Date;
}
