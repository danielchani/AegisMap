import { useEffect, useState } from "react";

/** Returns a timestamp (ms) refreshed every 30 s — used for relative age display. */
export function useNow(): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(id);
  }, []);
  return now;
}

/** Pure formatter. Pass the result of useNow() as `now`. */
export function formatScanAge(
  scannedAt: string | undefined,
  now: number,
): { label: string; isStale: boolean } {
  if (!scannedAt) return { label: "", isStale: false };
  const ageMin = Math.floor((now - new Date(scannedAt).getTime()) / 60_000);
  const label =
    ageMin < 1  ? "just now" :
    ageMin < 60 ? `${ageMin}m ago` :
    `${Math.floor(ageMin / 60)}h ago`;
  return { label, isStale: ageMin >= 10 };
}
