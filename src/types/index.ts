// Shared TypeScript types — mirrors Rust models in src-tauri/src/models/mod.rs

export type ScanProfile =
  | "quick_common_ports"
  | "standard_tcp"
  | "light_service_detection"
  | "os_detect"
  | "udp_common"
  | "stealth_syn"    // -sS half-open; requires root / Npcap
  | "ack_probe"      // -sA firewall mapping; requires root / Npcap
  | "evasion_scan";  // -sS -f + IP decoys; requires root / Npcap

export interface ScanRequest {
  target: string;
  profile: ScanProfile;
  portRange?: string;
  /** NSE scripts — validated backend-side against the curated allowlist. */
  scripts?: string[];
  /**
   * Decoy IPs for the nmap -D flag.
   * Comma-separated IPv4/IPv6 addresses plus ME/RND keywords.
   * Validated strictly server-side (max 8 entries, no shell metacharacters).
   * When omitted for evasion_scan, the backend defaults to RND:5.
   */
  decoys?: string;
  /**
   * Timing template override 0–4 (0=paranoid, 4=aggressive).
   * When omitted, the backend uses the profile's default (T2 for stealth, T4 otherwise).
   */
  timingOverride?: number;
  /**
   * Source port for --source-port spoofing (1–65535).
   * Useful for crossing stateful firewalls that trust specific source ports (e.g. 53, 80).
   */
  sourcePort?: number;
}

export interface PortEntry {
  port: number;
  protocol: string;
  state: string;
  service: string;
  product?: string;
  version?: string;
}

/** NSE script result parsed from nmap XML. */
export interface ScriptResult {
  id: string;
  output: string;
}

export interface PortsDiff {
  added:   number[];
  removed: number[];
}

/** Pentest engagement workflow state — frontend only. */
export type WorkflowStatus =
  | "discovered"
  | "enumerated"
  | "tested"
  | "vulnerable"
  | "mitigated";

export interface HostResult {
  address:         string;
  hostname?:       string;
  status:          string;
  ports:           PortEntry[];
  script_results?: ScriptResult[];  // from backend NSE parsing
  // Frontend-only fields (set in merge layer, not sent by backend)
  scannedAt?:      string;
  portsDiff?:      PortsDiff;
  notes?:          string;
  workflowStatus?: WorkflowStatus;
  tags?:           string[];                      // custom analyst tags
  portNotes?:      Record<string, string>;        // per-port notes keyed "port/protocol"
  portHistory?:    { ts: string; open: number }[]; // open-port count over time (last 10)
  httpProbes?:     HttpProbeResult[];             // opt-in HTTP surface probes (frontend-only)
  tlsProbes?:      TlsProbeResult[];             // opt-in TLS certificate probes (frontend-only)
}

export interface ScanReport {
  target: string;
  profile: ScanProfile;
  startedAt?: string;
  completedAt?: string;
  elapsedSeconds?: number;
  hosts: HostResult[];
}

export interface SavedSession {
  id: string;
  name: string;
  savedAt: string;
  hosts: HostResult[];
}

// Kept for backward compatibility
export interface ScanResult {
  hosts: HostResult[];
  elapsed_seconds: number;
}

/** Service family keys used by the port filter. */
export type PortFamily = "web" | "ssh" | "db" | "mail" | "dns" | null;

export function portFamily(port: number): PortFamily {
  if ([80, 443, 8080, 8443, 8000, 3000, 5000, 9000].includes(port)) return "web";
  if ([22, 2222, 222].includes(port))                                return "ssh";
  if ([3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984].includes(port)) return "db";
  if ([25, 465, 587, 143, 993, 110, 995].includes(port))             return "mail";
  if ([53, 5353].includes(port))                                     return "dns";
  return null;
}

export type ScanStreamEvent =
  | { type: "started" }
  | { type: "stdout_line";   data: { line: string } }
  | { type: "stderr_line";   data: { line: string } }
  | { type: "progress_hint"; data: { percent: number; etc_seconds?: number } }
  | { type: "parsed_result"; data: { report: ScanReport } }
  | { type: "completed";     data: { exit_code: number } }
  | { type: "cancelled" }
  | { type: "failed";        data: { message: string } };

export type ScanStatus =
  | "idle" | "starting" | "running" | "cancelling" | "completed" | "failed";

// ── Native HTTP/HTTPS surface intelligence ────────────────────────────────────

export interface SecurityHeaders {
  hsts?: string;
  contentSecurityPolicy?: string;
  xFrameOptions?: string;
  xContentTypeOptions?: string;
  xXssProtection?: string;
  referrerPolicy?: string;
  permissionsPolicy?: string;
  crossOriginOpenerPolicy?: string;
  crossOriginResourcePolicy?: string;
  crossOriginEmbedderPolicy?: string;
}

export interface HttpProbeResult {
  url: string;
  finalUrl: string;
  statusCode?: number;
  statusText?: string;
  title?: string;
  server?: string;
  xPoweredBy?: string;
  contentType?: string;
  responseTimeMs: number;
  responseSizeBytes?: number;
  securityHeaders: SecurityHeaders;
  /** Human-readable tech fingerprint strings, e.g. "Server: nginx/1.24" */
  technologyHints: string[];
  /** Network / TLS error — populated when the probe ran but failed at the transport level */
  error?: string;
  probedAt: string; // ISO-8601
}

export interface HttpProbeRequest {
  address: string;
  port: number;
  useHttps: boolean;
  followRedirects: boolean;
  timeoutSecs: number;
  acceptInvalidCerts: boolean;
}

// ── Native TLS/certificate intelligence ──────────────────────────────────────

export interface CertInfo {
  subjectCn?: string;
  /** DNS names and IP addresses from the Subject Alternative Name extension */
  subjectSan: string[];
  issuer?: string;
  notBefore: string;  // ISO-8601
  notAfter: string;   // ISO-8601
  /** Days until expiry; negative means already expired */
  daysUntilExpiry?: number;
  isSelfSigned: boolean;
  isExpired: boolean;
  serial?: string;    // colon-separated hex bytes
}

export interface TlsProbeResult {
  address: string;
  port: number;
  /** Negotiated TLS version, e.g. "TLS 1.3" */
  tlsVersion?: string;
  /** Negotiated cipher suite, e.g. "TLS13_AES_256_GCM_SHA384" */
  cipherSuite?: string;
  /** True for known-weak ciphers (RC4, DES, 3DES, EXPORT, NULL, ANON) */
  cipherIsWeak: boolean;
  /** Certificate chain — leaf first */
  certificateChain: CertInfo[];
  connectionTimeMs: number;
  error?: string;
  probedAt: string;  // ISO-8601
}

export interface TlsProbeRequest {
  address: string;
  port: number;
  timeoutSecs: number;
  acceptInvalidCerts: boolean;
}

export interface NmapStatus {
  installed: boolean;
  executablePath?: string;
  version?: string;
  error?: string;
}
