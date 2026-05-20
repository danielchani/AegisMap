/**
 * Bundled CVE database for local lookups — no outbound network requests.
 * Maps product+version patterns to known CVE entries.
 * Updated at build time; more comprehensive than port-based advisories.
 */

export interface CVEEntry {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  cvss: number;
  summary: string;
  affectedVersions: string; // version range description
  /** Regex pattern to match against detected version */
  versionPattern: RegExp;
}

export interface CVEProduct {
  product: string;
  aliases: string[];
  cves: CVEEntry[];
}

export const CVE_DATABASE: CVEProduct[] = [
  {
    product: "OpenSSH",
    aliases: ["openssh", "ssh"],
    cves: [
      { id: "CVE-2024-6387", severity: "critical", cvss: 9.8, summary: "regreSSHion — unauthenticated RCE via race condition in signal handler", affectedVersions: "8.5p1 to 9.7p1", versionPattern: /^(8\.[5-9]|9\.[0-7])/ },
      { id: "CVE-2023-51385", severity: "medium", cvss: 6.5, summary: "OS command injection via ssh:// ProxyCommand", affectedVersions: "<9.6", versionPattern: /^([0-8]\.|9\.[0-5])/ },
      { id: "CVE-2023-48795", severity: "medium", cvss: 5.9, summary: "Terrapin attack — prefix truncation in SSH binary packet protocol", affectedVersions: "<9.6", versionPattern: /^([0-8]\.|9\.[0-5])/ },
      { id: "CVE-2021-41617", severity: "high", cvss: 7.0, summary: "Privilege escalation via AuthorizedKeysCommand/AuthorizedPrincipalsCommand", affectedVersions: "6.2 to 8.7", versionPattern: /^([6-7]\.|8\.[0-7])/ },
      { id: "CVE-2020-15778", severity: "high", cvss: 7.8, summary: "Arbitrary command execution via scp with backtick filenames", affectedVersions: "<8.4", versionPattern: /^([0-7]\.|8\.[0-3])/ },
    ],
  },
  {
    product: "Apache",
    aliases: ["apache", "apache httpd", "httpd"],
    cves: [
      { id: "CVE-2024-38476", severity: "critical", cvss: 9.8, summary: "mod_proxy SSRF via websocket upgrade", affectedVersions: "2.4.0 to 2.4.59", versionPattern: /^2\.4\.(([0-4]\d?)|(5[0-9]))$/ },
      { id: "CVE-2023-25690", severity: "critical", cvss: 9.8, summary: "HTTP request smuggling via mod_proxy", affectedVersions: "2.4.0 to 2.4.55", versionPattern: /^2\.4\.(([0-4]\d?)|(5[0-5]))$/ },
      { id: "CVE-2021-41773", severity: "critical", cvss: 9.8, summary: "Path traversal and RCE via CGI", affectedVersions: "2.4.49 to 2.4.50", versionPattern: /^2\.4\.(49|50)$/ },
      { id: "CVE-2021-44790", severity: "critical", cvss: 9.8, summary: "Buffer overflow in mod_lua multipart parser", affectedVersions: "<2.4.52", versionPattern: /^2\.4\.(([0-4]\d?)|(5[01]))$/ },
    ],
  },
  {
    product: "nginx",
    aliases: ["nginx"],
    cves: [
      { id: "CVE-2024-7347", severity: "medium", cvss: 4.7, summary: "Worker process crash via specially crafted mp4 file", affectedVersions: "1.5.13 to 1.27.0", versionPattern: /^1\.(([5-9]|1\d|2[0-6])\.\d+|27\.0)/ },
      { id: "CVE-2022-41741", severity: "high", cvss: 7.8, summary: "Memory corruption in mp4 module", affectedVersions: "<1.23.2", versionPattern: /^1\.(([0-9]|1\d|2[0-2])\.|23\.[01])/ },
      { id: "CVE-2021-23017", severity: "critical", cvss: 9.4, summary: "DNS resolver off-by-one heap write", affectedVersions: "0.6.18 to 1.20.0", versionPattern: /^(0\.|1\.(([0-9]|1\d)\.|20\.0))/ },
    ],
  },
  {
    product: "MySQL",
    aliases: ["mysql", "mariadb"],
    cves: [
      { id: "CVE-2024-21047", severity: "medium", cvss: 4.9, summary: "Denial of service via InnoDB", affectedVersions: "<8.0.37", versionPattern: /^([0-7]\.|8\.0\.([0-2]\d|3[0-6]))/ },
      { id: "CVE-2023-21980", severity: "high", cvss: 7.1, summary: "Client protocol unspecified vulnerability", affectedVersions: "<8.0.33", versionPattern: /^([0-7]\.|8\.0\.([0-2]\d|3[0-2]))/ },
    ],
  },
  {
    product: "PostgreSQL",
    aliases: ["postgresql", "postgres"],
    cves: [
      { id: "CVE-2024-7348", severity: "high", cvss: 7.5, summary: "pg_dump TOCTOU race condition allows arbitrary SQL execution", affectedVersions: "<16.4, <15.8, <14.13", versionPattern: /^(([0-9]|1[0-3])\.|14\.(([0-9]|1[0-2])$)|15\.[0-7]$|16\.[0-3]$)/ },
      { id: "CVE-2023-5868", severity: "high", cvss: 8.1, summary: "Memory disclosure in aggregate function calls", affectedVersions: "<16.1, <15.5", versionPattern: /^(([0-9]|1[0-4])\.|15\.[0-4]$|16\.0$)/ },
    ],
  },
  {
    product: "Redis",
    aliases: ["redis"],
    cves: [
      { id: "CVE-2024-31449", severity: "high", cvss: 7.0, summary: "Lua library command ACL bypass and heap overflow", affectedVersions: "<7.2.6, <7.4.1", versionPattern: /^([0-6]\.|7\.([01]\.|2\.[0-5]$|3\.|4\.0$))/ },
      { id: "CVE-2023-41056", severity: "high", cvss: 8.1, summary: "Heap overflow in cjson/cmsgpack", affectedVersions: "<7.0.15, <7.2.4", versionPattern: /^([0-6]\.|7\.(0\.(([0-9]|1[0-4])$)|1\.|2\.[0-3]$))/ },
    ],
  },
  {
    product: "MongoDB",
    aliases: ["mongodb", "mongod"],
    cves: [
      { id: "CVE-2024-1351", severity: "critical", cvss: 9.1, summary: "Improper validation in mongos allows unauthorized access", affectedVersions: "5.0.0 to 7.0.4", versionPattern: /^([5-6]\.|7\.0\.[0-4]$)/ },
      { id: "CVE-2023-1409", severity: "high", cvss: 7.5, summary: "TLS cert validation bypass", affectedVersions: "<6.0.6, <5.0.17", versionPattern: /^([0-4]\.|5\.0\.(([0-9]|1[0-6])$)|6\.0\.[0-5]$)/ },
    ],
  },
  {
    product: "Samba",
    aliases: ["samba", "smbd"],
    cves: [
      { id: "CVE-2023-42670", severity: "medium", cvss: 6.5, summary: "AD DC busy loop denial of service", affectedVersions: "<4.19.1, <4.18.8", versionPattern: /^([0-3]\.|4\.(([0-9]|1[0-7])\.|18\.[0-7]$|19\.0$))/ },
      { id: "CVE-2022-45141", severity: "critical", cvss: 9.8, summary: "Kerberos RC4-HMAC ticket forgery (Heimdal)", affectedVersions: "<4.17.4", versionPattern: /^([0-3]\.|4\.(([0-9]|1[0-6])\.|17\.[0-3]$))/ },
      { id: "CVE-2021-44142", severity: "critical", cvss: 9.9, summary: "Heap out-of-bounds RW in vfs_fruit", affectedVersions: "<4.13.17", versionPattern: /^([0-3]\.|4\.(([0-9]|1[0-2])\.|13\.(([0-9]|1[0-6])$)))/ },
    ],
  },
  {
    product: "ProFTPD",
    aliases: ["proftpd"],
    cves: [
      { id: "CVE-2023-51713", severity: "high", cvss: 7.5, summary: "Out-of-bounds read in mod_sftp", affectedVersions: "<1.3.8b", versionPattern: /^1\.3\.[0-7]/ },
      { id: "CVE-2021-46854", severity: "high", cvss: 7.5, summary: "Memory corruption in mod_radius", affectedVersions: "<1.3.7c", versionPattern: /^1\.3\.[0-6]/ },
    ],
  },
  {
    product: "vsftpd",
    aliases: ["vsftpd"],
    cves: [
      { id: "CVE-2021-3618", severity: "high", cvss: 7.4, summary: "ALPACA — cross-protocol attack via TLS", affectedVersions: "<3.0.4", versionPattern: /^[0-2]\.|3\.0\.[0-3]$/ },
    ],
  },
  {
    product: "Elasticsearch",
    aliases: ["elasticsearch", "elastic"],
    cves: [
      { id: "CVE-2023-31419", severity: "high", cvss: 7.5, summary: "Stack overflow via nested aggregations", affectedVersions: "<8.9.1, <7.17.13", versionPattern: /^([0-6]\.|7\.(([0-9]|1[0-6])\.|17\.(([0-9]|1[0-2])$))|8\.([0-8]\.|9\.0$))/ },
    ],
  },
  {
    product: "OpenSSL",
    aliases: ["openssl"],
    cves: [
      { id: "CVE-2024-5535", severity: "critical", cvss: 9.1, summary: "Buffer overread in SSL_select_next_proto", affectedVersions: "<3.3.2, <3.2.3, <3.1.7, <3.0.15", versionPattern: /^([0-2]\.|3\.(0\.(([0-9]|1[0-4])$)|1\.[0-6]$|2\.[0-2]$|3\.[01]$))/ },
      { id: "CVE-2024-0727", severity: "medium", cvss: 5.5, summary: "NULL dereference processing malformed PKCS12", affectedVersions: "<3.2.1, <3.1.5, <3.0.13", versionPattern: /^([0-2]\.|3\.(0\.(([0-9]|1[0-2])$)|1\.[0-4]$|2\.0$))/ },
      { id: "CVE-2022-3602", severity: "high", cvss: 7.5, summary: "X.509 email address buffer overflow", affectedVersions: "3.0.0 to 3.0.6", versionPattern: /^3\.0\.[0-6]$/ },
    ],
  },
];

/**
 * Look up CVEs for a given product name and version string.
 * Returns matching CVE entries sorted by CVSS score (highest first).
 */
export function lookupCVEs(
  product: string | undefined,
  version: string | undefined,
): CVEEntry[] {
  if (!product || !version) return [];

  const normalizedProduct = product.toLowerCase().trim();

  for (const entry of CVE_DATABASE) {
    const matches =
      entry.product.toLowerCase() === normalizedProduct ||
      entry.aliases.some((a) => normalizedProduct.includes(a));

    if (matches) {
      const applicable = entry.cves.filter((cve) => {
        try {
          return cve.versionPattern.test(version);
        } catch {
          return false;
        }
      });
      return applicable.sort((a, b) => b.cvss - a.cvss);
    }
  }

  return [];
}

/**
 * Get a summary of CVE risk for a host across all detected services.
 */
export function hostCVESummary(
  ports: Array<{ product?: string; version?: string; state: string }>,
): { total: number; critical: number; high: number; medium: number; low: number; topCVE: CVEEntry | null } {
  let total = 0;
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let topCVE: CVEEntry | null = null;

  for (const port of ports) {
    if (port.state !== "open") continue;
    const cves = lookupCVEs(port.product, port.version);
    for (const cve of cves) {
      total++;
      if (cve.severity === "critical") critical++;
      else if (cve.severity === "high") high++;
      else if (cve.severity === "medium") medium++;
      else low++;
      if (!topCVE || cve.cvss > topCVE.cvss) topCVE = cve;
    }
  }

  return { total, critical, high, medium, low, topCVE };
}
