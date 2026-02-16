import { TrustStatus } from '../types/enums';

/**
 * Device metadata containing device characteristics
 */
export interface DeviceMetadata {
  deviceType: string;
  browser: string;
  operatingSystem: string;
  lastIpAddress: string;
}

/**
 * Device model representing recognized devices
 */
export interface Device {
  id: string;
  userId: string;
  identity: string;
  trustStatus: TrustStatus;
  revoked: boolean;
  firstSeen: Date;
  lastSeen: Date;
  metadata: DeviceMetadata;
}

/**
 * Device creation input
 */
export interface CreateDeviceInput {
  userId: string;
  identity: string;
  trustStatus?: TrustStatus;
  metadata: DeviceMetadata;
}

/**
 * Device update input
 */
export interface UpdateDeviceInput {
  trustStatus?: TrustStatus;
  revoked?: boolean;
  lastSeen?: Date;
  metadata?: Partial<DeviceMetadata>;
}
