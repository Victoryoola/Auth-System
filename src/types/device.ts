/**
 * Device information collected during authentication
 */
export interface DeviceInfo {
  userAgent: string;
  ipAddress: string;
  screenResolution?: string;
  timezone?: string;
  language?: string;
}
