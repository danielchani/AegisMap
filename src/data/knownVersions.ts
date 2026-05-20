/**
 * Static version advisory database — no network requests.
 * Maps product names (as reported by nmap) to latest/LTS versions and EOL notes.
 * Updated at build time; not a substitute for a live CVE feed.
 */

export interface VersionInfo {
  latest: string;
  lts?: string;
  eolNote?: string;
}

export const KNOWN_VERSIONS: Record<string, VersionInfo> = {
  // SSH
  "OpenSSH":         { latest: "9.7",   lts: "9.3",   eolNote: "<7.4 has many known CVEs" },
  // Web servers
  "nginx":           { latest: "1.27",  lts: "1.26" },
  "Apache":          { latest: "2.4.62",lts: "2.4.58", eolNote: "<2.4.50 has RCE (CVE-2021-41773)" },
  "Apache httpd":    { latest: "2.4.62",lts: "2.4.58", eolNote: "<2.4.50 has RCE (CVE-2021-41773)" },
  "lighttpd":        { latest: "1.4.76" },
  "IIS":             { latest: "10.0",  eolNote: "<7.5 is EOL" },
  // TLS
  "OpenSSL":         { latest: "3.3",   lts: "3.0",   eolNote: "<1.1.1 is EOL" },
  // FTP
  "ProFTPD":         { latest: "1.3.8",               eolNote: "<1.3.7 has known issues" },
  "vsftpd":          { latest: "3.0.5" },
  "Pure-FTPd":       { latest: "1.0.52" },
  // Mail
  "Postfix":         { latest: "3.9",   lts: "3.7" },
  "Exim":            { latest: "4.97",                eolNote: "<4.96 has known CVEs" },
  "Sendmail":        { latest: "8.18",                eolNote: "Consider migration to Postfix/Exim" },
  "Dovecot":         { latest: "2.3.21",lts: "2.3.19" },
  // SMB / Windows
  "Samba":           { latest: "4.20",  lts: "4.18",  eolNote: "<4.14 vulnerable (PrintNightmare)" },
  // Databases
  "MySQL":           { latest: "8.4",   lts: "8.0",   eolNote: "<5.7 is EOL" },
  "MariaDB":         { latest: "11.4",  lts: "10.11" },
  "PostgreSQL":      { latest: "16",    lts: "15",    eolNote: "<12 is EOL" },
  "MongoDB":         { latest: "7.0",   lts: "6.0",   eolNote: "<4.4 is EOL" },
  "Redis":           { latest: "7.4",   lts: "7.2" },
  "Elasticsearch":   { latest: "8.14",  lts: "7.17",  eolNote: "<7.10 may lack default auth" },
  // Remote access
  "OpenVPN":         { latest: "2.6",   lts: "2.5" },
  "Dropbear":        { latest: "2024.85" },
  // Misc
  "Python":          { latest: "3.13",  lts: "3.12",  eolNote: "<3.9 is EOL" },
  "PHP":             { latest: "8.3",   lts: "8.2",   eolNote: "<8.1 is EOL" },
  "Node.js":         { latest: "22",    lts: "20",    eolNote: "<18 is EOL" },
};

/** Parses a version string into comparable number array. */
function parseVer(v: string): number[] {
  return v.split(".").map((n) => parseInt(n, 10) || 0);
}

/** -1 if a < b, 0 if equal, 1 if a > b */
function cmpVer(a: string, b: string): number {
  const pa = parseVer(a);
  const pb = parseVer(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

export type VersionAdvisoryType = "ok" | "update" | "eol";

export interface VersionAdvisory {
  type: VersionAdvisoryType;
  message: string;
  latest: string;
}

/**
 * Returns an advisory if the detected version is outdated or EOL.
 * Returns null if the product is unknown or version is current.
 */
export function getVersionAdvisory(
  product: string | undefined,
  version: string | undefined,
): VersionAdvisory | null {
  if (!product || !version) return null;

  // Try exact match first, then prefix match (e.g. "Apache httpd" → "Apache")
  let info = KNOWN_VERSIONS[product];
  if (!info) {
    const key = Object.keys(KNOWN_VERSIONS).find((k) =>
      product.toLowerCase().startsWith(k.toLowerCase()),
    );
    if (key) info = KNOWN_VERSIONS[key];
  }
  if (!info) return null;

  const ref = info.lts ?? info.latest;
  const cmp = cmpVer(version, ref);

  if (cmp >= 0) {
    // Running latest/LTS — nothing to report
    return null;
  }

  // Outdated — check for EOL note
  if (info.eolNote && cmpVer(version, info.latest) < 0) {
    return {
      type: "eol",
      message: info.eolNote,
      latest: info.latest,
    };
  }

  return {
    type: "update",
    message: `Latest: ${info.latest}${info.lts ? ` (LTS: ${info.lts})` : ""}`,
    latest: info.latest,
  };
}
