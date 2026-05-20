/** Section label with accent diamond and trailing rule line. */
export function SLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "9px", letterSpacing: "0.18em", color: "var(--text-dim)", marginBottom: "6px" }}>
      <span style={{ color: "var(--accent)", opacity: 0.5 }}>◈</span>
      {children}
      <div style={{ flex: 1, height: "1px", background: "var(--border)" }} />
    </div>
  );
}
