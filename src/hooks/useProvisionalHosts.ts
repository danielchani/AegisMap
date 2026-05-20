import { useMemo } from "react";

export interface ProvisionalHost {
  address: string;
  openPorts: Array<{ port: number; protocol: string; service: string }>;
}

export function useProvisionalHosts(lines: string[]): ProvisionalHost[] {
  return useMemo(() => {
    const map = new Map<string, ProvisionalHost>();
    let cur: ProvisionalHost | null = null;

    for (const line of lines) {
      const hostM = line.match(/Nmap scan report for (.+)/);
      if (hostM) {
        const rest = hostM[1].trim();
        // Handle both "hostname (1.2.3.4)" and plain "1.2.3.4"
        const ipM = rest.match(/\(([^)]+)\)/);
        const addr = ipM ? ipM[1] : rest;
        if (!map.has(addr)) map.set(addr, { address: addr, openPorts: [] });
        cur = map.get(addr)!;
        continue;
      }
      if (cur) {
        const portM = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)/);
        if (portM) {
          cur.openPorts.push({
            port: parseInt(portM[1]),
            protocol: portM[2],
            service: portM[3],
          });
        }
      }
    }

    return Array.from(map.values());
  }, [lines]);
}
