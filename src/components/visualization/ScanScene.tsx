/**
 * Holographic Network Observatory — ScanScene
 *
 * State-driven animation vocabulary (strict):
 *  Continuous (running only): core glow breath · slow core rotation · flat port orbit · radar pulses
 *  One-shot: host spawn · discovery flash · finalization pulse per scan completion
 *  Static informational: service arc ring · risk glow · advisory badge · host info card
 *  Camera: smooth lerp toward selected host; preset buttons (fit/top/reset)
 */

import * as THREE from "three";
import { useMemo, useRef, useState } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { Html, Line, OrbitControls, Stars } from "@react-three/drei";
import { getAdvisory } from "../../data/cveHints";
import { getVersionAdvisory } from "../../data/knownVersions";
import { hostRiskLevel, RISK_COLOR, RISK_LABEL } from "../../lib/riskScore";
import { portColor } from "../../lib/ports";
import {
  getDiffState, getDiffColor, getDiffOpacity, DIFF_BADGE,
  getConfidenceTier, getConfidenceColor,
  type DiffState,
} from "../../lib/sceneMode";
import type { HostResult, PentestFinding, PortEntry, PortFamily, ScanReport, ScanStatus, SceneMode } from "../../types";
import { portFamily } from "../../types";
import type { ProvisionalHost } from "../../hooks/useProvisionalHosts";
import type { SessionDiffReport } from "../../lib/sessionDiff";

// ── Shared geometry ────────────────────────────────────────────────────────────
const GEO_HOST       = new THREE.SphereGeometry(0.32, 20, 20);
const GEO_PORT       = new THREE.SphereGeometry(0.065, 8, 8);
const GEO_RING_PULSE = new THREE.RingGeometry(0.90, 1.0, 64);
const GEO_RING_SEL   = new THREE.RingGeometry(0.50, 0.56, 48);

// ── Constants ──────────────────────────────────────────────────────────────────
const HOST_RADIUS  = 4.0;
const GHOST_RADIUS = 7.2;   // outer ring for diff-removed ghost nodes
const ORBIT_SPEED  = (Math.PI * 2) / 14;
const PULSE_PERIOD = 3.6;
const PULSE_MAX_R  = 7.2;
const GRID_Y       = -1.8;

// ── Service arc ring config ────────────────────────────────────────────────────
const SERVICE_ARCS = [
  { family: "web",   color: "#38bdf8", ports: new Set([80, 443, 8080, 8443, 8000, 3000, 5000, 9000]) },
  { family: "ssh",   color: "#4ade80", ports: new Set([22, 2222, 222]) },
  { family: "db",    color: "#fb923c", ports: new Set([3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984]) },
  { family: "mail",  color: "#fbbf24", ports: new Set([25, 465, 587, 143, 993, 110, 995]) },
  { family: "dns",   color: "#e879f9", ports: new Set([53, 5353]) },
  { family: "other", color: "#94a3b8", ports: new Set<number>() },
] as const;

const ALL_KNOWN_PORTS = new Set(SERVICE_ARCS.slice(0, 5).flatMap(f => [...f.ports]));

// ── Subnet palette ─────────────────────────────────────────────────────────────
const SUBNET_PALETTE = ["#00ffaa", "#38bdf8", "#a78bfa", "#fbbf24", "#e879f9"];

// ── Helpers ────────────────────────────────────────────────────────────────────

const easeOut = (t: number) => 1 - Math.pow(1 - t, 3);

function hostPosition(idx: number, total: number): [number, number, number] {
  if (total <= 1) return [total === 0 ? 0 : HOST_RADIUS, 0, 0];
  const angle = (idx / total) * Math.PI * 2 - Math.PI / 2;
  return [Math.cos(angle) * HOST_RADIUS, 0, Math.sin(angle) * HOST_RADIUS];
}

/** Positions removed hosts on a separate outer ring to avoid layout collisions. */
function ghostPosition(idx: number, total: number): [number, number, number] {
  if (total <= 1) return [GHOST_RADIUS, 0, 0];
  const angle = (idx / total) * Math.PI * 2 - Math.PI / 2;
  return [Math.cos(angle) * GHOST_RADIUS, 0, Math.sin(angle) * GHOST_RADIUS];
}

/** Y elevation = open port count × 0.16, capped at 1.6 units. */
function hostElevation(host: HostResult): number {
  return Math.min(host.ports.filter(p => p.state === "open").length, 10) * 0.16;
}

function subnetZones(hosts: HostResult[]): Array<{ label: string; center: [number, number, number]; radius: number; color: string }> {
  const subnet = (addr: string) => addr.split(".").slice(0, 3).join(".");
  const subnets = [...new Set(hosts.map(h => subnet(h.address)))];
  if (subnets.length <= 1) return [];
  const CLUSTER_DIST = 5.5;
  return subnets.map((s, si) => {
    const group = hosts.filter(h => subnet(h.address) === s);
    const sa = (si / subnets.length) * Math.PI * 2 - Math.PI / 2;
    const cx = Math.cos(sa) * CLUSTER_DIST;
    const cz = Math.sin(sa) * CLUSTER_DIST;
    const ir = group.length <= 1 ? 0.6 : Math.min(2.0, group.length * 0.55);
    return { label: `${s}.0/24`, center: [cx, 0, cz] as [number, number, number], radius: ir + 1.0, color: SUBNET_PALETTE[si % SUBNET_PALETTE.length] };
  });
}

function subnetColorMap(hosts: HostResult[]): Map<string, string> {
  const subnet = (addr: string) => addr.split(".").slice(0, 3).join(".");
  const subnets = [...new Set(hosts.map(h => subnet(h.address)))];
  const map = new Map<string, string>();
  hosts.forEach(h => { map.set(h.address, SUBNET_PALETTE[subnets.indexOf(subnet(h.address)) % SUBNET_PALETTE.length]); });
  return map;
}

/** Subnet-aware positions with Y elevation by open port count. */
function subnetAwarePositions(hosts: HostResult[]): Map<string, [number, number, number]> {
  const subnet = (addr: string) => addr.split(".").slice(0, 3).join(".");
  const subnets = [...new Set(hosts.map(h => subnet(h.address)))];
  const result  = new Map<string, [number, number, number]>();

  if (subnets.length <= 1) {
    hosts.forEach((h, i) => {
      const [x, , z] = hostPosition(i, hosts.length);
      result.set(h.address, [x, hostElevation(h), z]);
    });
    return result;
  }

  const CLUSTER_DIST = 5.5;
  for (let si = 0; si < subnets.length; si++) {
    const group = hosts.filter(h => subnet(h.address) === subnets[si]);
    const sa = (si / subnets.length) * Math.PI * 2 - Math.PI / 2;
    const cx = Math.cos(sa) * CLUSTER_DIST;
    const cz = Math.sin(sa) * CLUSTER_DIST;
    const ir = group.length <= 1 ? 0 : Math.min(2.0, group.length * 0.55);
    group.forEach((h, hi) => {
      const ia = group.length <= 1 ? 0 : (hi / group.length) * Math.PI * 2;
      result.set(h.address, [cx + Math.cos(ia) * ir, hostElevation(h), cz + Math.sin(ia) * ir]);
    });
  }
  return result;
}

/** Returns worst advisory severity across all open ports on a host. */
function hostAdvisoryLevel(host: HostResult): "critical" | "warning" | null {
  let worst: "critical" | "warning" | null = null;
  for (const p of host.ports.filter(p => p.state === "open")) {
    const cve = getAdvisory(p.port, p.service);
    if (cve && ["critical", "high"].includes(cve.severity)) return "critical";
    if (cve) worst = "warning";
    const ver = getVersionAdvisory(p.product, p.version);
    if (ver?.type === "eol") return "critical";
    if (ver?.type === "update") worst = "warning";
  }
  return worst;
}

// ── CameraRig ──────────────────────────────────────────────────────────────────

function CameraRig({ targetPos }: { targetPos: [number, number, number] | null }) {
  const controlsRef  = useRef<any>(null);
  const lerpedTarget = useRef(new THREE.Vector3(0, 0, 0));
  const goal         = useRef(new THREE.Vector3(0, 0, 0));

  useFrame((_, delta) => {
    if (!controlsRef.current) return;
    if (targetPos) {
      goal.current.set(targetPos[0] * 0.28, 0, targetPos[2] * 0.28);
    } else {
      goal.current.set(0, 0, 0);
    }
    lerpedTarget.current.lerp(goal.current, Math.min(1, delta * 2.5));
    controlsRef.current.target.copy(lerpedTarget.current);
    controlsRef.current.update();
  });

  return (
    <OrbitControls
      ref={controlsRef}
      enablePan={false}
      minDistance={5}
      maxDistance={28}
      maxPolarAngle={Math.PI / 2.05}
      makeDefault
    />
  );
}

// ── CameraPresets ──────────────────────────────────────────────────────────────

function CameraPresets({ positions }: { positions: Map<string, [number, number, number]> }) {
  const { camera, controls } = useThree();
  const ctrl = controls as any;

  function applyCamera(pos: [number, number, number], target: [number, number, number] = [0, 0, 0]) {
    camera.position.set(...pos);
    ctrl?.target?.set(...target);
    ctrl?.update?.();
  }

  function fitAll() {
    if (positions.size === 0) { applyCamera([0, 9, 13]); return; }
    const pts = Array.from(positions.values());
    const xs = pts.map(([x]) => x);
    const zs = pts.map(([,, z]) => z);
    const cx = (Math.min(...xs) + Math.max(...xs)) / 2;
    const cz = (Math.min(...zs) + Math.max(...zs)) / 2;
    const span = Math.max(Math.max(...xs) - Math.min(...xs), Math.max(...zs) - Math.min(...zs), 4);
    const dist = span * 0.9 + 5;
    applyCamera([cx, dist * 0.65, cz + dist * 0.75], [cx, 0, cz]);
  }

  const btn: React.CSSProperties = {
    width: "26px", height: "26px", fontSize: "13px", cursor: "pointer",
    background: "rgba(2,11,24,0.85)", color: "var(--text-dim)",
    border: "1px solid var(--border)", display: "flex",
    alignItems: "center", justifyContent: "center", transition: "all 0.15s",
  };

  return (
    <Html fullscreen>
      <div style={{ position: "absolute", bottom: "48px", right: "10px", display: "flex", flexDirection: "column", gap: "3px", zIndex: 9 }}>
        {([
          { icon: "⊡", title: "Fit all hosts",  fn: fitAll },
          { icon: "↑", title: "Top-down view",  fn: () => applyCamera([0, 22, 0.01]) },
          { icon: "↺", title: "Reset camera",   fn: () => applyCamera([0, 9, 13]) },
        ] as const).map(({ icon, title, fn }) => (
          <button key={icon} title={title} onClick={fn} style={btn}
            onMouseEnter={e => { e.currentTarget.style.color = "var(--accent)"; e.currentTarget.style.borderColor = "var(--accent)"; }}
            onMouseLeave={e => { e.currentTarget.style.color = "var(--text-dim)"; e.currentTarget.style.borderColor = "var(--border)"; }}
          >{icon}</button>
        ))}
      </div>
    </Html>
  );
}

// ── ScanCore ───────────────────────────────────────────────────────────────────

function ScanCore({ status }: { status: ScanStatus }) {
  const meshRef = useRef<THREE.Mesh>(null);
  const matRef  = useRef<THREE.MeshStandardMaterial>(null);
  const running = status === "running" || status === "starting";

  useFrame(({ clock }, delta) => {
    if (!meshRef.current || !matRef.current) return;
    meshRef.current.rotation.y += delta * (Math.PI * 2 / 25);
    if (running) {
      const breath = 0.5 + 0.5 * Math.sin(clock.elapsedTime * Math.PI * 0.8);
      matRef.current.emissiveIntensity = 0.45 + 0.85 * breath;
    } else {
      matRef.current.emissiveIntensity =
        status === "completed" ? 0.55 :
        status === "failed"    ? 0.22 : 0.18;
    }
  });

  const col = status === "failed" ? "#f87171" : "#00ffaa";
  return (
    <mesh ref={meshRef}>
      <icosahedronGeometry args={[0.32, 1]} />
      <meshStandardMaterial ref={matRef} color={col} emissive={col} emissiveIntensity={0.18} wireframe />
    </mesh>
  );
}

// ── RadarPulse ─────────────────────────────────────────────────────────────────

function RadarPulse({ phaseOffset }: { phaseOffset: number }) {
  const meshRef = useRef<THREE.Mesh>(null);
  const matRef  = useRef<THREE.MeshBasicMaterial>(null);
  const phase   = useRef(phaseOffset);

  useFrame((_, delta) => {
    if (!meshRef.current || !matRef.current) return;
    phase.current = (phase.current + delta / PULSE_PERIOD) % 1;
    const r = phase.current * PULSE_MAX_R;
    meshRef.current.scale.set(r, 1, r);
    matRef.current.opacity = Math.max(0, 0.36 * (1 - phase.current));
  });

  return (
    <mesh ref={meshRef} geometry={GEO_RING_PULSE} rotation={[-Math.PI / 2, 0, 0]}>
      <meshBasicMaterial ref={matRef} color="#00ffaa" transparent opacity={0} side={THREE.DoubleSide} />
    </mesh>
  );
}

// ── FinalizationPulse ──────────────────────────────────────────────────────────

function FinalizationPulse({ id }: { id: number }) {
  const meshRef = useRef<THREE.Mesh>(null);
  const matRef  = useRef<THREE.MeshBasicMaterial>(null);
  const phase   = useRef(1);
  const prevId  = useRef(0);

  useFrame((_, delta) => {
    if (!meshRef.current || !matRef.current) return;
    if (id !== prevId.current) { prevId.current = id; phase.current = 0; }
    if (phase.current < 1) {
      phase.current = Math.min(1, phase.current + delta / 1.6);
      const r = easeOut(phase.current) * 8.5;
      meshRef.current.scale.set(r, 1, r);
      matRef.current.opacity = Math.max(0, (1 - phase.current) * 0.5);
      meshRef.current.visible = true;
    } else {
      meshRef.current.visible = false;
    }
  });

  return (
    <mesh ref={meshRef} geometry={GEO_RING_PULSE} rotation={[-Math.PI / 2, 0, 0]} visible={false}>
      <meshBasicMaterial ref={matRef} color="#00ffaa" transparent opacity={0} side={THREE.DoubleSide} />
    </mesh>
  );
}

// ── ServiceArcRing ─────────────────────────────────────────────────────────────
// Always-visible ring showing service category distribution. Dims when host is
// selected so the individual port orbs can be read more easily.

function ServiceArcRing({ openPorts, selected }: { openPorts: PortEntry[]; selected: boolean }) {
  if (openPorts.length === 0) return null;

  const counts = SERVICE_ARCS.map(f => ({
    color: f.color,
    count: f.family === "other"
      ? openPorts.filter(p => !ALL_KNOWN_PORTS.has(p.port)).length
      : openPorts.filter(p => (f.ports as Set<number>).has(p.port)).length,
  })).filter(a => a.count > 0);

  const total = openPorts.length;
  const GAP   = 0.055; // radians between arcs

  const segments: { color: string; start: number; len: number }[] = [];
  let angle = 0;
  for (const arc of counts) {
    const full = (arc.count / total) * Math.PI * 2;
    const len  = full - GAP;
    if (len > 0.02) segments.push({ color: arc.color, start: angle + GAP / 2, len });
    angle += full;
  }

  return (
    <group rotation={[-Math.PI / 2, 0, 0]}>
      {segments.map((seg, i) => (
        <mesh key={i}>
          <ringGeometry args={[0.47, 0.61, 48, 1, seg.start, seg.len]} />
          <meshBasicMaterial color={seg.color} transparent opacity={selected ? 0.28 : 0.82} side={THREE.DoubleSide} />
        </mesh>
      ))}
    </group>
  );
}

// ── PortOrb ────────────────────────────────────────────────────────────────────

interface PortLike { port: number; service?: string; protocol?: string }

// PortOrb always shows its label (it only mounts when the host is selected).
// The label dims on un-hover; hovering highlights it.
function PortOrb({ port, orbitRadius, initialAngle, filter }: {
  port: PortLike; orbitRadius: number; initialAngle: number; filter: PortFamily;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const matRef  = useRef<THREE.MeshBasicMaterial>(null);
  const angle   = useRef(initialAngle);
  const spawnT  = useRef(0);
  const col     = portColor(port.port);
  const [hovered, setHovered] = useState(false);

  useFrame((_, delta) => {
    if (!meshRef.current || !matRef.current) return;
    if (spawnT.current < 1) spawnT.current = Math.min(1, spawnT.current + delta * 3);
    angle.current += ORBIT_SPEED * delta;
    meshRef.current.position.set(
      Math.cos(angle.current) * orbitRadius, 0,
      Math.sin(angle.current) * orbitRadius,
    );
    const matches = !filter || portFamily(port.port) === filter;
    matRef.current.opacity = easeOut(spawnT.current) * (matches ? 1 : 0.12);
  });

  return (
    <mesh
      ref={meshRef}
      geometry={GEO_PORT}
      scale={1.1}
      onPointerOver={e => { e.stopPropagation(); setHovered(true); }}
      onPointerOut={() => setHovered(false)}
    >
      {/* meshBasicMaterial — visible regardless of scene lighting level */}
      <meshBasicMaterial ref={matRef} color={col} transparent opacity={0} />
      <Html position={[0, 0.18, 0]} center distanceFactor={7} zIndexRange={[20, 0]} style={{ pointerEvents: "none" }}>
        <div style={{
          display: "flex", alignItems: "center", gap: "3px",
          fontSize: hovered ? "10px" : "8px",
          fontFamily: "monospace", letterSpacing: "0.04em",
          color: col,
          background: hovered ? "rgba(2,8,16,0.97)" : "rgba(2,8,16,0.80)",
          border: `1px solid ${col}${hovered ? "99" : "44"}`,
          padding: "1px 5px",
          whiteSpace: "nowrap",
          transition: "all 0.1s",
        }}>
          <span style={{ fontWeight: 700 }}>{port.port}</span>
          <span style={{ opacity: 0.65 }}>/{port.service || port.protocol || "?"}</span>
        </div>
      </Html>
    </mesh>
  );
}

// ── HeartbeatRing ──────────────────────────────────────────────────────────────

function HeartbeatRing() {
  const phase = useRef(0);
  const mesh  = useRef<THREE.Mesh>(null);
  const mat   = useRef<THREE.MeshBasicMaterial>(null);
  useFrame((_, delta) => {
    if (!mesh.current || !mat.current) return;
    phase.current = (phase.current + delta / 4) % 1;
    const r = 0.52 + phase.current * 0.38;
    mesh.current.scale.set(r / 0.52, 1, r / 0.52);
    mat.current.opacity = Math.max(0, 0.6 * (1 - phase.current));
  });
  return (
    <mesh ref={mesh} geometry={GEO_RING_SEL} rotation={[-Math.PI / 2, 0, 0]}>
      <meshBasicMaterial ref={mat} color="#ffffff" transparent opacity={0.6} side={THREE.DoubleSide} />
    </mesh>
  );
}

// ── RiskGlow ───────────────────────────────────────────────────────────────────
// Coloured disc projected on the grid below each host. Radius and opacity scale
// with risk level — makes session threat distribution readable at a glance.

const GLOW_RADIUS:  Record<string, number> = { clean: 0.30, low: 0.50, medium: 0.80, high: 1.10, critical: 1.55 };
const GLOW_OPACITY: Record<string, number> = { clean: 0.07, low: 0.11, medium: 0.16, high: 0.22, critical: 0.30 };

function RiskGlow({ x, z, risk, colorOverride, radiusOverride }: {
  x: number; z: number; risk: string;
  colorOverride?: string; radiusOverride?: number;
}) {
  const col     = colorOverride ?? (RISK_COLOR[risk as keyof typeof RISK_COLOR] ?? "#4ade80");
  const radius  = radiusOverride ?? (GLOW_RADIUS[risk]  ?? 0.30);
  const opacity = GLOW_OPACITY[risk] ?? 0.07;

  return (
    <group position={[x, GRID_Y + 0.01, z]}>
      {/* Soft glow fill */}
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <circleGeometry args={[radius, 32]} />
        <meshBasicMaterial color={col} transparent opacity={opacity} side={THREE.DoubleSide} />
      </mesh>
      {/* Sharp ring edge */}
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[radius * 0.82, radius, 32]} />
        <meshBasicMaterial color={col} transparent opacity={opacity * 1.6} side={THREE.DoubleSide} />
      </mesh>
    </group>
  );
}

// ── AdvisoryBadge ──────────────────────────────────────────────────────────────
// Floating ⚠ above hosts that have CVE advisories or EOL/outdated versions.
// Red = high/critical CVE or EOL product. Amber = medium/low CVE or update available.

function AdvisoryBadge({ host }: { host: HostResult }) {
  const level = hostAdvisoryLevel(host);
  if (!level) return null;

  const col   = level === "critical" ? "#e11d48" : "#fb923c";
  const label = level === "critical" ? "⚠ RISK"  : "⚠";

  return (
    <Html position={[0.42, 0.50, 0]} center distanceFactor={9} zIndexRange={[14, 0]} style={{ pointerEvents: "none" }}>
      <div style={{
        fontSize: "8px", fontFamily: "monospace", letterSpacing: "0.06em",
        color: col, background: "rgba(2,6,14,0.93)",
        border: `1px solid ${col}`,
        padding: "0 4px", lineHeight: "15px",
        boxShadow: `0 0 8px ${col}44`,
      }}>
        {label}
      </div>
    </Html>
  );
}

// ── HostInfoCard ───────────────────────────────────────────────────────────────
// Holographic info panel shown next to the selected host. Displays risk score,
// service category breakdown, workflow status, tags, and scan age.

const WORKFLOW_COL: Record<string, string> = {
  discovered: "#38bdf8", enumerated: "#a78bfa", tested: "#fbbf24",
  vulnerable: "#f87171", mitigated:  "#6b7280",
};

function HostInfoCard({ host, findings }: { host: HostResult; findings?: PentestFinding[] }) {
  const openPorts = useMemo(() => host.ports.filter(p => p.state === "open"), [host.ports]);
  const risk    = hostRiskLevel(host, findings);
  const riskCol = RISK_COLOR[risk];

  const cats = useMemo(() => [
    { label: "WEB",  color: "#38bdf8", count: openPorts.filter(p => portFamily(p.port) === "web").length  },
    { label: "SSH",  color: "#4ade80", count: openPorts.filter(p => portFamily(p.port) === "ssh").length  },
    { label: "DB",   color: "#fb923c", count: openPorts.filter(p => portFamily(p.port) === "db").length   },
    { label: "MAIL", color: "#fbbf24", count: openPorts.filter(p => portFamily(p.port) === "mail").length },
    { label: "DNS",  color: "#e879f9", count: openPorts.filter(p => portFamily(p.port) === "dns").length  },
  ].filter(c => c.count > 0), [openPorts]);

  const uncategorized = openPorts.length - cats.reduce((s, c) => s + c.count, 0);

  const age = useMemo(() => {
    if (!host.scannedAt) return null;
    const mins = Math.floor((Date.now() - new Date(host.scannedAt).getTime()) / 60000);
    return mins < 1 ? "just now" : mins < 60 ? `${mins}m ago` : `${Math.floor(mins / 60)}h ago`;
  }, [host.scannedAt]);

  // Advisory count for quick summary
  const advisoryLevel = useMemo(() => hostAdvisoryLevel(host), [host]);

  // Card sits directly above the node label so it's always centred on-screen
  return (
    <Html position={[0, 1.92, 0]} center distanceFactor={7.5} zIndexRange={[16, 0]} style={{ pointerEvents: "none" }}>
      <div style={{
        background: "rgba(2,8,20,0.97)",
        border: `1px solid ${riskCol}44`,
        boxShadow: `0 4px 24px rgba(0,0,0,0.75), 0 0 0 1px ${riskCol}18`,
        padding: "7px 10px",
        minWidth: "128px",
        fontFamily: "monospace",
        fontSize: "9px",
        letterSpacing: "0.05em",
        color: "rgba(168,204,184,0.8)",
      }}>
        {/* Risk header */}
        <div style={{ color: riskCol, fontWeight: 700, fontSize: "8px", letterSpacing: "0.15em", marginBottom: "5px", paddingBottom: "4px", borderBottom: `1px solid ${riskCol}30` }}>
          ◈ {RISK_LABEL[risk]}
          {advisoryLevel && (
            <span style={{ float: "right", color: advisoryLevel === "critical" ? "#e11d48" : "#fb923c", fontSize: "9px" }}>⚠</span>
          )}
        </div>

        {/* Service categories */}
        <div style={{ marginBottom: "5px", display: "flex", flexWrap: "wrap", gap: "2px 8px" }}>
          {cats.map(c => (
            <span key={c.label} style={{ color: c.color }}>
              {c.label}&nbsp;<span style={{ opacity: 0.75 }}>{c.count}</span>
            </span>
          ))}
          {uncategorized > 0 && (
            <span style={{ color: "rgba(255,255,255,0.3)" }}>+{uncategorized}</span>
          )}
          {openPorts.length === 0 && <span style={{ color: "rgba(255,255,255,0.25)" }}>no open ports</span>}
        </div>

        {/* Total open */}
        <div style={{ color: "rgba(255,255,255,0.35)", marginBottom: openPorts.length ? "4px" : 0, fontSize: "8px" }}>
          {openPorts.length} open port{openPorts.length !== 1 ? "s" : ""}
        </div>

        {/* Workflow status */}
        {host.workflowStatus && (
          <div style={{ color: WORKFLOW_COL[host.workflowStatus] ?? "rgba(255,255,255,0.4)", fontSize: "8px", letterSpacing: "0.1em", marginBottom: "3px" }}>
            {host.workflowStatus.toUpperCase()}
          </div>
        )}

        {/* Tags */}
        {(host.tags?.length ?? 0) > 0 && (
          <div style={{ color: "#38bdf8", fontSize: "8px", marginBottom: "3px", opacity: 0.75, overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", maxWidth: "120px" }}>
            {host.tags!.slice(0, 3).join(" · ")}
          </div>
        )}

        {/* Scan age */}
        {age && (
          <div style={{ color: "rgba(255,255,255,0.22)", fontSize: "8px" }}>{age}</div>
        )}

        {/* ── Intelligence probes ─────────────────────────────────── */}
        {((host.httpProbes?.length ?? 0) > 0 || (host.tlsProbes?.length ?? 0) > 0 || host.notes) && (
          <div style={{ marginTop: "5px", paddingTop: "5px", borderTop: "1px solid rgba(255,255,255,0.08)" }}>

            {/* Latest HTTP probe — status + title */}
            {(host.httpProbes?.length ?? 0) > 0 && (() => {
              const p = host.httpProbes![host.httpProbes!.length - 1];
              const sc = p.statusCode;
              const scCol = sc == null ? "rgba(255,255,255,0.3)"
                : sc < 300 ? "#4ade80"
                : sc < 400 ? "#38bdf8"
                : sc < 500 ? "#fbbf24"
                : "#f87171";
              return (
                <div style={{ display: "flex", gap: "4px", alignItems: "baseline", marginBottom: "3px", overflow: "hidden" }}>
                  <span style={{ color: "#38bdf8", opacity: 0.6, flexShrink: 0 }}>HTTP</span>
                  {sc && <span style={{ color: scCol, fontWeight: 700 }}>{sc}</span>}
                  {p.error
                    ? <span style={{ color: "#f87171", opacity: 0.7, fontSize: "8px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>✗ {p.error.slice(0, 28)}</span>
                    : p.title && <span style={{ color: "rgba(255,255,255,0.55)", fontSize: "8px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>&nbsp;{p.title.slice(0, 24)}</span>
                  }
                </div>
              );
            })()}

            {/* Latest TLS probe — version + cert CN + expiry */}
            {(host.tlsProbes?.length ?? 0) > 0 && (() => {
              const t = host.tlsProbes![host.tlsProbes!.length - 1];
              const leaf = t.certificateChain[0];
              const expColor = leaf?.isExpired ? "#f87171"
                : (leaf?.daysUntilExpiry ?? 999) < 30 ? "#fbbf24"
                : "#4ade80";
              return (
                <div style={{ display: "flex", gap: "4px", alignItems: "baseline", marginBottom: "3px", overflow: "hidden" }}>
                  <span style={{ color: "#a78bfa", opacity: 0.6, flexShrink: 0 }}>TLS</span>
                  {t.error
                    ? <span style={{ color: "#f87171", opacity: 0.7, fontSize: "8px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>✗ {t.error.slice(0, 28)}</span>
                    : <>
                        {t.tlsVersion && <span style={{ color: "#a78bfa" }}>{t.tlsVersion.replace("TLS ", "")}</span>}
                        {t.cipherIsWeak && <span style={{ color: "#fbbf24", fontSize: "8px" }}>⚠</span>}
                        {leaf?.subjectCn && <span style={{ color: "rgba(255,255,255,0.55)", fontSize: "8px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>&nbsp;{leaf.subjectCn.slice(0, 20)}</span>}
                        {leaf?.daysUntilExpiry != null && (
                          <span style={{ color: expColor, fontSize: "8px", flexShrink: 0, marginLeft: "2px" }}>
                            {leaf.isExpired ? "EXPIRED" : `${leaf.daysUntilExpiry}d`}
                          </span>
                        )}
                      </>
                  }
                </div>
              );
            })()}
          </div>
        )}

        {/* ── Analyst note (first line) ───────────────────────────── */}
        {host.notes && (
          <div style={{
            marginTop: "5px", paddingTop: "5px", borderTop: "1px solid rgba(255,255,255,0.08)",
            color: "rgba(255,255,255,0.45)", fontSize: "8px", fontStyle: "italic",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "148px",
          }}>
            "{host.notes.split("\n")[0].slice(0, 40)}"
          </div>
        )}
      </div>
    </Html>
  );
}

// ── HostNode ───────────────────────────────────────────────────────────────────

function HostNode({
  host, position, selected, onSelect, portFilter, subnetColor, showLabels = true,
  sceneMode = "network", diffState = "none", confidenceOverall, findings,
}: {
  host: HostResult; position: [number, number, number]; selected: boolean;
  onSelect: () => void; portFilter: PortFamily; subnetColor?: string; showLabels?: boolean;
  sceneMode?: SceneMode; diffState?: DiffState; confidenceOverall?: number;
  findings?: PentestFinding[];
}) {
  const groupRef = useRef<THREE.Group>(null);
  const matRef   = useRef<THREE.MeshStandardMaterial>(null);
  const spawnT   = useRef(0);
  const flashT   = useRef(0);
  const { camera } = useThree();
  const [spawned, setSpawned] = useState(false);

  const up   = host.status === "up";
  const risk = hostRiskLevel(host, findings);
  const baseCol = up ? (subnetColor ?? RISK_COLOR[risk]) : "#f87171";
  const networkCol = host.workflowStatus === "vulnerable" ? "#f87171"
                   : host.workflowStatus === "mitigated"  ? "#4b5563"
                   : baseCol;

  // Mode-specific color
  const col = sceneMode === "diff"
    ? getDiffColor(diffState)
    : sceneMode === "confidence"
      ? getConfidenceColor(getConfidenceTier(confidenceOverall ?? 0))
      : networkCol;

  // Diff mode: dim unchanged hosts
  const nodeOpacity = (sceneMode === "diff") ? getDiffOpacity(diffState) : 1.0;
  const isTransparent = nodeOpacity < 1.0;

  const openPorts = useMemo(() => host.ports.filter(p => p.state === "open").slice(0, 8), [host.ports]);
  const nodeScale = 0.85 + Math.min(openPorts.length, 8) * 0.018;

  useFrame((_, delta) => {
    if (!groupRef.current || !matRef.current) return;
    if (spawnT.current < 1) {
      spawnT.current = Math.min(1, spawnT.current + delta * 2.5);
      groupRef.current.scale.setScalar(nodeScale * easeOut(spawnT.current));
      if (spawnT.current >= 0.75 && !spawned) setSpawned(true);
    }
    if (spawnT.current >= 1 && flashT.current < 1) {
      flashT.current = Math.min(1, flashT.current + delta / 0.5);
      matRef.current.emissiveIntensity = (selected ? 1.5 : 0.65) + 3.0 * (1 - flashT.current);
    } else {
      matRef.current.emissiveIntensity = selected ? 1.5 : 0.65;
    }
  });

  // Label LOD — recompute once per frame, only trigger setCamDist if the bucket changes
  const camBucket = useRef<"close" | "mid" | "far">("mid");
  const [labelMode, setLabelMode] = useState<"full" | "ip" | "none">("ip");
  useFrame(() => {
    const d = camera.position.distanceTo(new THREE.Vector3(...position));
    const bucket = d < 12 ? "close" : d <= 20 ? "mid" : "far";
    if (bucket !== camBucket.current) {
      camBucket.current = bucket;
      setLabelMode(bucket === "close" ? "full" : bucket === "mid" ? "ip" : "none");
    }
  });

  return (
    <group position={position}>
      {/* Scaled group — spawn animation only. Port orbs live OUTSIDE this group
          so the scale={0} JSX prop never interferes with their visibility. */}
      <group ref={groupRef} scale={0}>
        <mesh geometry={GEO_HOST} onClick={e => { e.stopPropagation(); onSelect(); }}>
          <meshStandardMaterial ref={matRef}
            color={selected ? "#e8fff4" : col}
            emissive={col}
            emissiveIntensity={selected ? 1.5 : 0.65}
            transparent={isTransparent}
            opacity={nodeOpacity}
          />
        </mesh>
        {selected && <HeartbeatRing />}
        <ServiceArcRing openPorts={openPorts} selected={selected} />
      </group>

      {/* Port orbs — outside the scaled group; only rendered when selected */}
      {selected && openPorts.map((p, pi) => {
        const tilt = ((pi % 5) - 2) * 0.21;
        return (
          <group key={`${p.port}/${p.protocol}`} rotation={[tilt, 0, 0]}>
            <PortOrb
              port={p}
              orbitRadius={0.72 + pi * 0.12}
              initialAngle={(pi / openPorts.length) * Math.PI * 2}
              filter={portFilter}
            />
          </group>
        );
      })}

      {/* Advisory badge */}
      {spawned && <AdvisoryBadge host={host} />}

      {/* Holographic info card — selected only, positioned above the node */}
      {selected && <HostInfoCard host={host} findings={findings} />}

      {/* Label — LOD levels (suppressed by showLabels filter) */}
      {showLabels && labelMode !== "none" && (
        <Html position={[0, 0.74, 0]} center distanceFactor={9} zIndexRange={[10, 0]} style={{ pointerEvents: "none" }}>
          <div style={{
            fontSize: "11px", fontFamily: "monospace", letterSpacing: "0.05em",
            color: selected ? "#ffffff" : col,
            background: "rgba(2,11,24,0.9)",
            padding: "2px 7px",
            border: `1px solid ${selected ? "rgba(255,255,255,0.3)" : col + "33"}`,
            whiteSpace: "nowrap",
            opacity: nodeOpacity < 1 ? 0.55 : 1,
          }}>
            {sceneMode === "diff" && DIFF_BADGE[diffState] && (
              <span style={{ marginRight: "4px", color: col }}>{DIFF_BADGE[diffState]}</span>
            )}
            {host.address}
            {labelMode === "full" && host.hostname && (
              <span style={{ opacity: 0.45, fontSize: "9px", marginLeft: "5px" }}>{host.hostname}</span>
            )}
            {sceneMode === "confidence" && labelMode === "full" && (
              <span style={{ opacity: 0.65, fontSize: "9px", marginLeft: "5px" }}>[{confidenceOverall ?? 0}%]</span>
            )}
          </div>
          {labelMode === "full" && sceneMode === "network" && (
            <div style={{ marginTop: "2px", fontSize: "9px", fontFamily: "monospace", textAlign: "center", color: col + "77" }}>
              {openPorts.length > 0 ? `${openPorts.length} open · ${risk}` : host.status}
            </div>
          )}
        </Html>
      )}
    </group>
  );
}

// ── ProvisionalNode ────────────────────────────────────────────────────────────

function ProvisionalNode({ host, idx, total }: { host: ProvisionalHost; idx: number; total: number }) {
  const groupRef = useRef<THREE.Group>(null);
  const spawnT   = useRef(0);
  const basePos  = useMemo(() => hostPosition(idx, total), [idx, total]);

  useFrame((_, delta) => {
    if (!groupRef.current) return;
    if (spawnT.current < 1) {
      spawnT.current = Math.min(1, spawnT.current + delta * 2.5);
      groupRef.current.scale.setScalar(0.85 + 0.15 * easeOut(spawnT.current));
    }
  });

  const provPorts = useMemo<PortEntry[]>(() =>
    host.openPorts.map(p => ({ port: p.port, protocol: "tcp", state: "open", service: p.service ?? "" })),
    [host.openPorts]);

  return (
    <group position={basePos}>
      <group ref={groupRef} scale={0.85}>
        <mesh geometry={GEO_HOST}>
          <meshStandardMaterial color="#253a30" emissive="#0d2216" emissiveIntensity={0.4} transparent opacity={0.45} />
        </mesh>
        <ServiceArcRing openPorts={provPorts.slice(0, 6)} selected={false} />
      </group>
      <Html position={[0, 0.68, 0]} center distanceFactor={9} zIndexRange={[5, 0]} style={{ pointerEvents: "none" }}>
        <div style={{
          fontSize: "10px", fontFamily: "monospace",
          color: "rgba(0,255,170,0.36)", background: "rgba(2,11,8,0.85)",
          padding: "1px 5px", border: "1px solid rgba(0,255,170,0.1)",
          whiteSpace: "nowrap", letterSpacing: "0.04em",
        }}>
          {host.address} …
        </div>
      </Html>
    </group>
  );
}

// ── DiffGhostNode ─────────────────────────────────────────────────────────────
// Semi-transparent ghost for hosts that existed in the baseline but are now gone.

function DiffGhostNode({ host, position }: { host: HostResult; position: [number, number, number] }) {
  const groupRef = useRef<THREE.Group>(null);
  const spawnT   = useRef(0);
  useFrame((_, delta) => {
    if (!groupRef.current) return;
    if (spawnT.current < 1) {
      spawnT.current = Math.min(1, spawnT.current + delta * 1.8);
      groupRef.current.scale.setScalar(easeOut(spawnT.current));
    }
  });
  return (
    <group position={position}>
      <group ref={groupRef} scale={0}>
        <mesh geometry={GEO_HOST}>
          <meshStandardMaterial color="#475569" emissive="#1e293b" emissiveIntensity={0.5}
            transparent opacity={0.35} />
        </mesh>
        {/* Dashed ring to distinguish from live nodes */}
        <mesh geometry={GEO_RING_SEL} rotation={[-Math.PI / 2, 0, 0]} scale={[1.1, 1, 1.1]}>
          <meshBasicMaterial color="#475569" transparent opacity={0.4} side={THREE.DoubleSide} />
        </mesh>
      </group>
      <Html position={[0, 0.72, 0]} center distanceFactor={9} zIndexRange={[8, 0]} style={{ pointerEvents: "none" }}>
        <div style={{
          fontSize: "10px", fontFamily: "monospace",
          color: "rgba(71,85,105,0.8)", background: "rgba(2,11,24,0.88)",
          padding: "1px 6px", border: "1px solid rgba(71,85,105,0.3)",
          whiteSpace: "nowrap", letterSpacing: "0.04em",
        }}>
          ⊖ {host.address}
        </div>
      </Html>
    </group>
  );
}

// ── ConfidenceRing ────────────────────────────────────────────────────────────
// Partial arc ring showing reconnaissance completeness (0–100%).

function ConfidenceRing({ overall, color, position }: {
  overall: number; color: string; position: [number, number, number];
}) {
  const geo = useMemo(
    () => new THREE.RingGeometry(0.44, 0.49, 48, 1, 0, Math.max(0.01, (overall / 100) * Math.PI * 2)),
    [overall],
  );
  return (
    <mesh geometry={geo} position={[position[0], position[1] + 0.45, position[2]]} rotation={[-Math.PI / 2, 0, 0]}>
      <meshBasicMaterial color={color} transparent opacity={0.8} side={THREE.DoubleSide} />
    </mesh>
  );
}

// ── SubnetZone ─────────────────────────────────────────────────────────────────

function SubnetZone({ label, center, radius, color }: { label: string; center: [number, number, number]; radius: number; color: string }) {
  return (
    <group position={center}>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.01, 0]}>
        <circleGeometry args={[radius, 48]} />
        <meshBasicMaterial color={color} transparent opacity={0.04} side={THREE.DoubleSide} />
      </mesh>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.01, 0]}>
        <ringGeometry args={[radius - 0.06, radius, 48]} />
        <meshBasicMaterial color={color} transparent opacity={0.22} side={THREE.DoubleSide} />
      </mesh>
      <Html position={[0, 0.08, radius - 0.1]} center distanceFactor={10} zIndexRange={[3, 0]} style={{ pointerEvents: "none" }}>
        <div style={{ fontSize: "8px", fontFamily: "monospace", color: color + "77", letterSpacing: "0.08em", whiteSpace: "nowrap" }}>
          {label}
        </div>
      </Html>
    </group>
  );
}

// ── SceneGrid ──────────────────────────────────────────────────────────────────

function SceneGrid() {
  return (
    <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, GRID_Y, 0]}>
      <planeGeometry args={[40, 40, 22, 22]} />
      <meshBasicMaterial color="#061825" wireframe transparent opacity={0.12} />
    </mesh>
  );
}

// ── ConnectionLine ─────────────────────────────────────────────────────────────
// Pulses briefly in opacity when finalizationId increments.

function ConnectionLine({ from, to, color, selected, finalizationId }: {
  from: [number, number, number]; to: [number, number, number];
  color: string; selected: boolean; finalizationId: number;
}) {
  const phaseRef = useRef(1);
  const prevId   = useRef(0);
  const [opacity, setOpacity] = useState(selected ? 0.55 : 0.2);

  useFrame((_, delta) => {
    if (finalizationId !== prevId.current) { prevId.current = finalizationId; phaseRef.current = 0; }
    if (phaseRef.current < 1) {
      phaseRef.current = Math.min(1, phaseRef.current + delta / 1.5);
      const t = phaseRef.current;
      const pulse = t < 0.5 ? t * 2 : (1 - t) * 2;
      setOpacity((selected ? 0.55 : 0.2) + 0.6 * pulse);
    } else {
      setOpacity(selected ? 0.55 : 0.2);
    }
  });

  return (
    <Line points={[from, to]} color={color} lineWidth={selected ? 1.3 : 0.6} transparent opacity={opacity} />
  );
}

// ── ScanScene ──────────────────────────────────────────────────────────────────

interface ScanSceneProps {
  status: ScanStatus;
  report: ScanReport | null;
  finalizationId: number;
  provisionalHosts: ProvisionalHost[];
  selectedHost: HostResult | null;
  portFilter: PortFamily;
  onSelectHost: (h: HostResult | null) => void;
  showLabels?: boolean;
  showConnections?: boolean;
  visibleRiskLevels?: Set<string>;
  sceneMode?: SceneMode;
  diffReport?: SessionDiffReport | null;
  diffRemovedHosts?: HostResult[];
  visibleDiffStates?: Set<string>;
  confidenceMap?: Map<string, number>;
  findings?: PentestFinding[];
}

export function ScanScene({
  status, report, finalizationId,
  provisionalHosts, selectedHost, portFilter, onSelectHost,
  showLabels = true,
  showConnections = true,
  visibleRiskLevels,
  sceneMode = "network",
  diffReport = null,
  diffRemovedHosts = [],
  visibleDiffStates,
  confidenceMap,
  findings,
}: ScanSceneProps) {
  const running   = status === "starting" || status === "running";
  const allHosts  = report?.hosts ?? [];
  // Apply risk-level filter (network mode only) — hidden hosts stay in data but leave scene
  const authHosts = (sceneMode === "network" && visibleRiskLevels)
    ? allHosts.filter(h => visibleRiskLevels.has(hostRiskLevel(h, findings)))
    : allHosts;
  // In diff mode: further filter by visible diff states
  const filteredHosts = (sceneMode === "diff" && visibleDiffStates)
    ? authHosts.filter(h => {
        const state = getDiffState(h.address, diffReport);
        return visibleDiffStates.has(state === "none" ? "added" : state);
      })
    : authHosts;
  const showProv  = running && authHosts.length === 0;

  const positions    = useMemo(() => subnetAwarePositions(filteredHosts), [filteredHosts]);
  const ghostPositions = useMemo(
    () => diffRemovedHosts.map((_, i) => ghostPosition(i, diffRemovedHosts.length)),
    [diffRemovedHosts],
  );
  const zones        = useMemo(() => subnetZones(filteredHosts), [filteredHosts]);
  const subnetColors = useMemo(() => subnetColorMap(filteredHosts), [filteredHosts]);
  const cameraTarget = selectedHost ? (positions.get(selectedHost.address) ?? null) : null;

  return (
    <Canvas
      camera={{ position: [0, 9, 13], fov: 46 }}
      style={{ width: "100%", height: "100%", background: "#020b18" }}
      onPointerMissed={() => onSelectHost(null)}
      gl={{ antialias: true, alpha: false, preserveDrawingBuffer: true }}
    >
      {/* Depth fog */}
      <fog attach="fog" args={["#020b18", 14, 28]} />

      {/* Lighting */}
      <ambientLight intensity={0.2} color="#061f33" />
      <pointLight position={[0, 8, 0]}   intensity={75} color="#00ffaa" decay={2} />
      <pointLight position={[6, 3, 6]}   intensity={28} color="#004488" decay={2} />
      <pointLight position={[-5, 2, -4]} intensity={16} color="#002255" decay={2} />

      {/* Stars + grid */}
      <Stars radius={100} depth={70} count={1600} factor={2.5} saturation={0.1} fade />
      <SceneGrid />

      {/* Floor glow — risk in network mode; diff/confidence color in other modes */}
      {filteredHosts.map(h => {
        const pos  = positions.get(h.address) ?? ([0, 0, 0] as [number, number, number]);
        const risk = hostRiskLevel(h, findings);
        const glowColor = sceneMode === "diff"
          ? getDiffColor(getDiffState(h.address, diffReport))
          : sceneMode === "confidence"
            ? getConfidenceColor(getConfidenceTier(confidenceMap?.get(h.address) ?? 0))
            : undefined;
        const glowRadius = sceneMode === "diff" ? 0.55 : undefined;
        return <RiskGlow key={`glow-${h.address}`} x={pos[0]} z={pos[2]} risk={risk}
          colorOverride={glowColor} radiusOverride={glowRadius} />;
      })}

      {/* Subnet zone boundaries (network mode only — avoid clutter in diff/confidence) */}
      {sceneMode === "network" && zones.map(z => (
        <SubnetZone key={z.label} label={z.label} center={z.center} radius={z.radius} color={z.color} />
      ))}

      {/* Central scanner node */}
      <ScanCore status={status} />

      {/* Radar pulses — running only */}
      {running && <RadarPulse phaseOffset={0} />}
      {running && <RadarPulse phaseOffset={0.5} />}

      {/* Finalization pulse */}
      <FinalizationPulse id={finalizationId} />

      {/* Connection lines */}
      {showConnections && showProv && provisionalHosts.map((h, i) => (
        <Line key={`pl-${h.address}`}
          points={[[0, 0, 0], hostPosition(i, provisionalHosts.length)]}
          color="#00ffaa" lineWidth={0.6} transparent opacity={0.13}
          dashed dashSize={0.28} gapSize={0.18}
        />
      ))}
      {showConnections && filteredHosts.map(h => {
        const sel  = selectedHost?.address === h.address;
        const risk = hostRiskLevel(h, findings);
        const networkCol = subnetColors.size > 1
          ? (subnetColors.get(h.address) ?? RISK_COLOR[risk])
          : (h.status === "up" ? RISK_COLOR[risk] : "#f87171");
        const col = sceneMode === "diff"
          ? getDiffColor(getDiffState(h.address, diffReport))
          : sceneMode === "confidence"
            ? getConfidenceColor(getConfidenceTier(confidenceMap?.get(h.address) ?? 0))
            : networkCol;
        const pos = positions.get(h.address) ?? ([0, 0, 0] as [number, number, number]);
        return (
          <ConnectionLine key={`al-${h.address}`}
            from={[0, 0, 0]} to={pos}
            color={col} selected={sel}
            finalizationId={finalizationId}
          />
        );
      })}

      {/* Provisional hosts */}
      {showProv && provisionalHosts.map((h, i) => (
        <ProvisionalNode key={h.address} host={h} idx={i} total={provisionalHosts.length} />
      ))}

      {/* Authoritative hosts */}
      {filteredHosts.map(h => (
        <HostNode key={h.address}
          host={h}
          position={positions.get(h.address) ?? [0, 0, 0]}
          selected={selectedHost?.address === h.address}
          onSelect={() => onSelectHost(h)}
          portFilter={portFilter}
          subnetColor={subnetColors.size > 1 ? subnetColors.get(h.address) : undefined}
          showLabels={showLabels}
          sceneMode={sceneMode}
          diffState={getDiffState(h.address, diffReport)}
          confidenceOverall={confidenceMap?.get(h.address)}
          findings={findings}
        />
      ))}

      {/* Diff mode: ghost nodes for removed hosts */}
      {sceneMode === "diff" && (!visibleDiffStates || visibleDiffStates.has("removed")) &&
        diffRemovedHosts.map((h, i) => (
          <DiffGhostNode key={`ghost-${h.address}`} host={h} position={ghostPositions[i] ?? [0, 0, 0]} />
        ))
      }

      {/* Confidence mode: arc rings showing completeness */}
      {sceneMode === "confidence" && filteredHosts.map(h => {
        const pos     = positions.get(h.address) ?? ([0, 0, 0] as [number, number, number]);
        const overall = confidenceMap?.get(h.address) ?? 0;
        const tier    = getConfidenceTier(overall);
        return (
          <ConfidenceRing key={`conf-${h.address}`}
            overall={overall}
            color={getConfidenceColor(tier)}
            position={[pos[0], pos[1], pos[2]]}
          />
        );
      })}

      {/* Camera rig + presets */}
      <CameraRig targetPos={cameraTarget} />
      <CameraPresets positions={positions} />
    </Canvas>
  );
}
