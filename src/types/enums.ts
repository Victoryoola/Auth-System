/**
 * Session trust levels based on risk assessment
 */
export enum SessionTrustLevel {
  FULL_TRUST = 'FULL_TRUST',
  LIMITED_TRUST = 'LIMITED_TRUST',
  UNVERIFIED = 'UNVERIFIED',
  HIGH_RISK = 'HIGH_RISK',
}

/**
 * Device trust status
 */
export enum TrustStatus {
  TRUSTED = 'TRUSTED',
  UNTRUSTED = 'UNTRUSTED',
  PENDING = 'PENDING',
}

/**
 * Verification methods for step-up authentication
 */
export enum VerificationMethod {
  EMAIL_OTP = 'EMAIL_OTP',
  SMS_OTP = 'SMS_OTP',
  AUTHENTICATOR_APP = 'AUTHENTICATOR_APP',
}
