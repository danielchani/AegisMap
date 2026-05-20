/**
 * Shared port classification constants and utilities.
 * Single source of truth — imported by HostInspector, ScanScene, suggestions,
 * playbooks, and ScannerPanel instead of local redefinitions.
 */

export const WEB_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 3000, 4443, 5000, 9000]);

export const TLS_PORTS = new Set([443, 8443, 4443, 636, 993, 995, 465, 5986, 8883]);

export const DB_PORTS = new Set([3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984]);

export const SSH_PORTS = new Set([22, 2222, 222]);

export const MAIL_PORTS = new Set([25, 465, 587, 143, 993, 110, 995]);

export const DNS_PORTS = new Set([53, 5353]);

export const FTP_PORTS = new Set([21, 20, 990]);

export const SMB_PORTS = new Set([445, 139, 135]);

/** Returns a colour string for a port number, used in port tables and 3D orbs. */
export function portColor(port: number): string {
  if (SSH_PORTS.has(port))  return "#4ade80";
  if (WEB_PORTS.has(port))  return "#38bdf8";
  if (FTP_PORTS.has(port))  return "#a78bfa";
  if (MAIL_PORTS.has(port)) return "#fbbf24";
  if (DB_PORTS.has(port))   return "#fb923c";
  if (DNS_PORTS.has(port))  return "#e879f9";
  if (SMB_PORTS.has(port))  return "#94a3b8";
  return "#67e8f9";
}
