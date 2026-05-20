/**
 * Static security advisory lookup — no network requests, no new attack surface.
 * Port-based advisories take precedence; service-name advisories are a fallback.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Advisory {
  label: string;
  detail: string;
  severity: Severity;
}

export const PORT_ADVISORIES: Record<number, Advisory> = {
  21:    { label: "FTP",      detail: "Cleartext credentials — consider SFTP/FTPS",        severity: "medium"   },
  23:    { label: "TELNET",   detail: "Cleartext protocol — replace with SSH",              severity: "high"     },
  69:    { label: "TFTP",     detail: "No authentication mechanism",                       severity: "high"     },
  135:   { label: "MSRPC",    detail: "RPC endpoint mapper exposed to network",            severity: "medium"   },
  139:   { label: "NETBIOS",  detail: "Legacy NetBIOS — enables host enumeration",         severity: "medium"   },
  445:   { label: "SMB",      detail: "SMB exposed — ensure fully patched (EternalBlue)",  severity: "high"     },
  512:   { label: "REXEC",    detail: "Legacy remote execution — no auth encryption",      severity: "high"     },
  513:   { label: "RLOGIN",   detail: "rlogin is obsolete; replace with SSH",              severity: "high"     },
  514:   { label: "RSH",      detail: "rsh is obsolete; replace with SSH",                severity: "high"     },
  1433:  { label: "MSSQL",    detail: "Database port exposed to network",                  severity: "medium"   },
  1521:  { label: "ORACLE",   detail: "Database port exposed to network",                  severity: "medium"   },
  2049:  { label: "NFS",      detail: "NFS share exposed — verify export restrictions",   severity: "medium"   },
  3306:  { label: "MYSQL",    detail: "Database port exposed to network",                  severity: "medium"   },
  3389:  { label: "RDP",      detail: "Ensure Network Level Authentication is enforced",  severity: "medium"   },
  5432:  { label: "POSTGRES", detail: "Database port exposed to network",                  severity: "medium"   },
  5900:  { label: "VNC",      detail: "Verify strong authentication is required",          severity: "medium"   },
  6379:  { label: "REDIS",    detail: "Redis is often unauthenticated by default",         severity: "high"     },
  9200:  { label: "ELASTIC",  detail: "Older Elasticsearch may have no authentication",   severity: "high"     },
  11211: { label: "MEMCACHE", detail: "Memcached has no authentication mechanism",         severity: "high"     },
  27017: { label: "MONGODB",  detail: "MongoDB may lack authentication by default",        severity: "high"     },
};

export const SERVICE_ADVISORIES: Record<string, Advisory> = {
  telnet:          { label: "CLEARTEXT",   detail: "Telnet transmits credentials unencrypted",    severity: "high"   },
  ftp:             { label: "CLEARTEXT",   detail: "FTP transmits credentials unencrypted",       severity: "medium" },
  rlogin:          { label: "DEPRECATED",  detail: "rlogin is obsolete; use SSH",                severity: "high"   },
  rsh:             { label: "DEPRECATED",  detail: "rsh is obsolete; use SSH",                  severity: "high"   },
  rexec:           { label: "DEPRECATED",  detail: "rexec is obsolete; use SSH",                severity: "high"   },
  vnc:             { label: "SCREEN SHARE",detail: "VNC exposed — verify authentication required",severity: "medium" },
  redis:           { label: "NOAUTH RISK", detail: "Redis often runs unauthenticated by default",severity: "high"   },
  mongodb:         { label: "NOAUTH RISK", detail: "MongoDB may lack auth by default",           severity: "high"   },
  memcache:        { label: "NOAUTH",      detail: "Memcached has no authentication mechanism",  severity: "high"   },
  "ms-wbt-server": { label: "RDP",         detail: "Ensure NLA is enforced on RDP",              severity: "medium" },
  nfs:             { label: "NFS",         detail: "Verify NFS export restrictions",             severity: "medium" },
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  info:     "#38bdf8",
  low:      "#fbbf24",
  medium:   "#fb923c",
  high:     "#f87171",
  critical: "#e11d48",
};

export function getAdvisory(port: number, service?: string): Advisory | null {
  if (PORT_ADVISORIES[port])  return PORT_ADVISORIES[port];
  if (service) return SERVICE_ADVISORIES[service.toLowerCase()] ?? null;
  return null;
}
