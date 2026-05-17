// Shared TypeScript types — populated in Phase 2+

export type ScanProfile =
  | "QuickCommonPorts"
  | "StandardTcp"
  | "LightServiceDetection";

export interface ScanRequest {
  target: string;
  profile: ScanProfile;
}

export interface PortEntry {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
}

export interface HostResult {
  address: string;
  hostname: string;
  ports: PortEntry[];
}

export interface ScanResult {
  hosts: HostResult[];
  elapsed_seconds: number;
}

export type LogEvent =
  | { type: "Line"; content: string }
  | { type: "Cancelled" }
  | { type: "Done" };
