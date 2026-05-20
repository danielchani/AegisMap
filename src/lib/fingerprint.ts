/**
 * Host fingerprint confidence scoring and passive data enrichment.
 * Extracts identity information from Nmap output: PTR records, SSL cert fields,
 * banner data, and service detection confidence.
 */

import type { HostResult } from "../types";

export interface FingerprintConfidence {
  /** Overall confidence 0-100 (base score + probe enrichment bonus, capped at 100) */
  overall: number;
  /** Breakdown by category */
  breakdown: {
    serviceDetection: number;   // how many open ports have service+version
    osDetection: number;        // 0 or 100 based on whether OS was detected
    scriptEnrichment: number;   // how many enrichment scripts ran
    bannerGrab: number;         // percentage of ports with banner data
    // Probe enrichment bonus (+5 each when the respective probe has been run)
    httpEnrichment: number;     // 0 or 5
    tlsEnrichment: number;      // 0 or 5
    dnsEnrichment: number;      // 0 or 5
  };
  /** Suggested follow-up scans to improve confidence */
  suggestions: string[];
}

export interface HostIdentity {
  /** Probable hostname from PTR/cert/banner */
  probableHostnames: string[];
  /** Organization from SSL cert */
  organization?: string;
  /** SSL certificate details */
  sslInfo?: {
    subject: string;
    issuer: string;
    validUntil?: string;
    sans: string[];
  };
  /** Technology stack inferred from services */
  techStack: string[];
  /** Banner strings per port */
  banners: Array<{ port: number; banner: string }>;
}

/** Calculate fingerprint confidence for a host */
export function calculateConfidence(host: HostResult): FingerprintConfidence {
  const openPorts = host.ports.filter((p) => p.state === "open");
  if (openPorts.length === 0) {
    return {
      overall: 0,
      breakdown: { serviceDetection: 0, osDetection: 0, scriptEnrichment: 0, bannerGrab: 0, httpEnrichment: 0, tlsEnrichment: 0, dnsEnrichment: 0 },
      suggestions: ["Run a service detection scan (-sV) to identify running services"],
    };
  }

  // Service detection: % of open ports with service + version
  const withService = openPorts.filter((p) => p.service && p.service !== "unknown").length;
  const withVersion = openPorts.filter((p) => p.version).length;
  const serviceDetection = Math.round(
    ((withService / openPorts.length) * 60 + (withVersion / openPorts.length) * 40)
  );

  // OS detection: binary — did we get OS info?
  const osDetection = host.hostname ? 50 : 0; // rough proxy

  // Script enrichment: how many scripts ran vs how many could
  const scriptCount = host.script_results?.length ?? 0;
  const possibleScripts = Math.min(openPorts.length * 2, 16); // rough estimate
  const scriptEnrichment = possibleScripts > 0
    ? Math.min(100, Math.round((scriptCount / possibleScripts) * 100))
    : 0;

  // Banner grab: % of ports with product info
  const withProduct = openPorts.filter((p) => p.product).length;
  const bannerGrab = Math.round((withProduct / openPorts.length) * 100);

  const base = Math.round(
    serviceDetection * 0.35 +
    osDetection * 0.15 +
    scriptEnrichment * 0.25 +
    bannerGrab * 0.25
  );

  // Probe enrichment bonus: +5 per probe type that has been run, capped at 100
  const httpEnrichment = (host.httpProbes?.length ?? 0) > 0 ? 5 : 0;
  const tlsEnrichment  = (host.tlsProbes?.length ?? 0)  > 0 ? 5 : 0;
  const dnsEnrichment  = (host.dnsResults?.length ?? 0)  > 0 ? 5 : 0;
  const overall = Math.min(100, base + httpEnrichment + tlsEnrichment + dnsEnrichment);

  const suggestions: string[] = [];
  if (serviceDetection < 50) {
    suggestions.push("Run SERVICE profile to detect versions on open ports");
  }
  if (osDetection === 0) {
    suggestions.push("Run OS DETECT profile (requires root/admin) for OS fingerprinting");
  }
  if (scriptEnrichment < 30) {
    suggestions.push("Enable NSE scripts (banner, ssl-cert, http-title) for deeper enumeration");
  }
  if (bannerGrab < 40) {
    suggestions.push("Enable banner grab script to capture service banners");
  }

  // Probe enrichment suggestions (shown only when the probe hasn't been run yet)
  const hasWebPort = openPorts.some((p) => [80, 443, 8080, 8443, 8000, 3000, 5000, 9000].includes(p.port));
  const hasTlsPort = openPorts.some((p) => [443, 8443, 4443, 636, 993, 995, 465].includes(p.port));
  if (httpEnrichment === 0 && hasWebPort) {
    suggestions.push("Run HTTP probe on web port to improve surface coverage (+5)");
  }
  if (tlsEnrichment === 0 && hasTlsPort) {
    suggestions.push("Run TLS probe to extract certificate evidence (+5)");
  }
  if (dnsEnrichment === 0 && host.hostname) {
    suggestions.push("Run DNS query to verify host identity (+5)");
  }

  return {
    overall,
    breakdown: { serviceDetection, osDetection, scriptEnrichment, bannerGrab, httpEnrichment, tlsEnrichment, dnsEnrichment },
    suggestions,
  };
}

/** Extract identity information from passive scan data */
export function extractIdentity(host: HostResult): HostIdentity {
  const probableHostnames: string[] = [];
  const techStack: string[] = [];
  const banners: Array<{ port: number; banner: string }> = [];
  let organization: string | undefined;
  let sslInfo: HostIdentity["sslInfo"];

  // Hostname from Nmap
  if (host.hostname) {
    probableHostnames.push(host.hostname);
  }

  // Parse SSL cert script results
  const sslCert = host.script_results?.find((s) => s.id === "ssl-cert");
  if (sslCert) {
    const subjectMatch = sslCert.output.match(/Subject:\s*(.+?)(?:\n|$)/i);
    const issuerMatch  = sslCert.output.match(/Issuer:\s*(.+?)(?:\n|$)/i);
    const sanMatch     = sslCert.output.match(/Subject Alternative Name:\s*(.+?)(?:\n|$)/i);
    const validMatch   = sslCert.output.match(/Not valid after:\s*(.+?)(?:\n|$)/i);

    const subject = subjectMatch?.[1]?.trim() ?? "";
    const issuer  = issuerMatch?.[1]?.trim() ?? "";
    const sans: string[] = [];

    if (sanMatch) {
      const sanStr = sanMatch[1];
      const dnsNames = sanStr.match(/DNS:([^\s,]+)/gi);
      if (dnsNames) {
        dnsNames.forEach((d) => {
          const name = d.replace(/^DNS:/i, "");
          sans.push(name);
          if (!probableHostnames.includes(name)) probableHostnames.push(name);
        });
      }
    }

    // Extract CN from subject
    const cnMatch = subject.match(/CN=([^\s,/]+)/i);
    if (cnMatch && !probableHostnames.includes(cnMatch[1])) {
      probableHostnames.push(cnMatch[1]);
    }

    // Extract org
    const orgMatch = subject.match(/O=([^,/]+)/i);
    if (orgMatch) organization = orgMatch[1].trim();

    sslInfo = {
      subject,
      issuer,
      validUntil: validMatch?.[1]?.trim(),
      sans,
    };
  }

  // Parse banner results
  const bannerResult = host.script_results?.find((s) => s.id === "banner");
  if (bannerResult) {
    // Banner format is typically "port/protocol: banner text"
    const lines = bannerResult.output.split("\n").filter(Boolean);
    for (const line of lines) {
      const match = line.match(/^(\d+)\//);
      if (match) {
        banners.push({ port: parseInt(match[1], 10), banner: line });
      }
    }
  }

  // Build tech stack from detected products
  const openPorts = host.ports.filter((p) => p.state === "open");
  for (const port of openPorts) {
    if (port.product && !techStack.includes(port.product)) {
      const entry = port.version ? `${port.product} ${port.version}` : port.product;
      techStack.push(entry);
    }
  }

  // Parse HTTP title for technology hints
  const httpTitle = host.script_results?.find((s) => s.id === "http-title");
  if (httpTitle) {
    const titleMatch = httpTitle.output.match(/title:\s*(.+?)(?:\n|$)/i);
    if (titleMatch) {
      const title = titleMatch[1].trim();
      // Common tech hints from page titles
      if (/wordpress/i.test(title)) techStack.push("WordPress");
      if (/joomla/i.test(title)) techStack.push("Joomla");
      if (/drupal/i.test(title)) techStack.push("Drupal");
      if (/tomcat/i.test(title)) techStack.push("Apache Tomcat");
      if (/iis/i.test(title)) techStack.push("Microsoft IIS");
      if (/gitlab/i.test(title)) techStack.push("GitLab");
      if (/jenkins/i.test(title)) techStack.push("Jenkins");
      if (/grafana/i.test(title)) techStack.push("Grafana");
    }
  }

  // Parse server header
  const serverHeader = host.script_results?.find((s) => s.id === "http-server-header");
  if (serverHeader) {
    const server = serverHeader.output.trim();
    if (server && !techStack.some((t) => server.toLowerCase().includes(t.toLowerCase()))) {
      techStack.push(server);
    }
  }

  return {
    probableHostnames,
    organization,
    sslInfo,
    techStack,
    banners,
  };
}
