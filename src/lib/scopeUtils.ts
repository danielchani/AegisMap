/** Converts an IPv4 string to a 32-bit unsigned integer. */
function ipToInt(ip: string): number {
  return ip.split(".").reduce((acc, oct) => ((acc << 8) | parseInt(oct, 10)) >>> 0, 0) >>> 0;
}

/** Returns true if `ip` falls within the given CIDR range or exact IP. */
function isInCIDR(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf("/");
  if (slash === -1) return ip === cidr; // exact match
  const bits = parseInt(cidr.slice(slash + 1), 10);
  const mask = bits === 0 ? 0 : (~((1 << (32 - bits)) - 1)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(cidr.slice(0, slash)) & mask);
}

/** Checks whether a scan target string falls within any of the authorised ranges.
 *  Returns true when no ranges are defined (open scope). */
export function isInScope(target: string, ranges: string[]): boolean {
  if (ranges.length === 0) return true;
  // Extract the IP part from targets like "host (1.2.3.4)" or plain IPs
  const ipMatch = target.match(/(?:\()?(\d{1,3}(?:\.\d{1,3}){3})(?:\))?/);
  const ip = ipMatch ? ipMatch[1] : target;
  return ranges.some((r) => {
    try { return isInCIDR(ip, r.trim()); }
    catch { return false; }
  });
}

/** Validates a scope range entry — accepts same chars as target validator plus /. */
export function validateScopeRange(input: string): string | null {
  const t = input.trim();
  if (!t) return "Range must not be empty";
  if (!/^[\w.\-:/\[\]*]+$/.test(t)) return "Invalid characters in range";
  return null;
}
