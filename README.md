# AegisMap

A desktop network reconnaissance tool built on Tauri 2 + React + Rust. AegisMap runs Nmap scans, streams results in real time, parses the authoritative XML output, and renders a live 3D holographic view of discovered hosts and open ports — with persistent sessions, risk scoring, CVE lookups, fingerprint confidence scoring, analyst workflow tracking, and export capabilities.

---

## Features

### Scanning & Intelligence
| Feature | Details |
|---|---|
| **8 scan profiles** | Quick (top 100 TCP), Standard TCP (all ports), Light Service Detection (versions), OS Detect (root), UDP Common (top 20 UDP), Stealth SYN (half-open -sS), ACK Probe (firewall mapping -sA), Evasion Scan (decoys + fragmentation) |
| **Stealth SYN scan** | `-sS` half-open TCP scan — never completes the handshake; quieter than connect scan and avoids most application-layer logging. Requires root (Linux) or Npcap + Administrator (Windows). T2 timing by default. |
| **ACK probe** | `-sA` scans reveal firewall rulesets: ports returning RST are unfiltered; dropped packets are filtered. Useful for firewall auditing. Requires root / Npcap. |
| **Evasion scan** | `-sS -f -D` — combines SYN scan, IP packet fragmentation, and IP decoys. Fragmentation defeats naive signature-based IDS; decoys (default: RND:5 random IPs) flood firewall logs with spurious source addresses. Requires root / Npcap. **For authorised testing only.** |
| **IP decoys** | User-supplied or auto-generated (`RND:N`) decoy IPs passed to nmap `-D`; validated strictly (max 8, no shell metacharacters). Available on any stealth profile. |
| **Source-port spoofing** | Optional `--source-port` value (1–65535) to cross stateful firewalls that trust traffic from privileged source ports (e.g. DNS/53, HTTP/80). Validated server-side. |
| **Privilege error detection** | Nmap's privilege/Npcap error messages are intercepted and replaced with a clear actionable message instead of a raw exit-code failure. |
| **Custom port range** | Optional `22,80,443` or `1-1024` override per scan |
| **NSE scripts** | 8 curated read-only scripts: http-title, ssl-cert, ssh-hostkey, smb-security-mode, ftp-anon, banner, http-headers, http-server-header |
| **Live streaming** | Nmap stdout/stderr streamed line-by-line via Tauri Channels with real-time progress + ETA |
| **XML parsing** | Authoritative results including NSE script output from nmap's `-oX` |
| **Re-scan single host** | One-click re-scan with current profile; port diff shown after |
| **Scan queue** | Queue multiple targets — auto-chains to next target on scan completion |
| **Engagement scope** | Define authorised CIDR ranges; targets outside scope show inline warning with Proceed / Cancel |
| **Scan timeout** | Per-profile hard timeout (90s–600s); watchdog kills nmap and emits a clear error |
| **Bundled CVE database** | Local database covering 12 products (OpenSSH, Apache, nginx, MySQL, PostgreSQL, Redis, MongoDB, Samba, ProFTPD, vsftpd, Elasticsearch, OpenSSL) with 30+ CVE entries, CVSS scores, and version-pattern matching — zero network requests |
| **Fingerprint confidence** | Per-host confidence score (0–100) with breakdown across service detection, OS detection, script enrichment, and banner grab — with actionable suggestions to improve coverage |
| **Host identity extraction** | Passive identity enrichment from SSL certs (CN, SANs, org), banners, HTTP titles, and server headers — builds probable hostnames and tech stack |
| **Session diffing** | Compare two scan snapshots to detect added/removed/changed hosts and port-level changes (new ports, removed ports, version changes) |

### Session Management
| Feature | Details |
|---|---|
| **Session accumulation** | Multiple scans merge hosts by address — no duplicates |
| **Port merging** | Re-scanning the same host unions port results; version info from latest scan wins |
| **Port change diff** | NEW / removed ports highlighted after a re-scan |
| **localStorage persistence** | Active session survives app restarts automatically |
| **File-based persistence** | Sessions saved as JSON files via Rust IPC to the app data directory with path-traversal-safe ID sanitisation |
| **Named sessions** | Save, load, and delete named session snapshots via inline UI (no browser dialogs) |
| **Session import** | Import a previously exported JSON file with deep schema validation and input sanitisation; invalid entries rejected with count |
| **Export JSON / CSV / Markdown** | Three export formats in the actions area |
| **Per-host remove** | Remove individual hosts without clearing everything |

### Analysis & Reporting
| Feature | Details |
|---|---|
| **Attack surface dashboard** | Per-session metrics: host count, open ports, risk distribution bar, weighted score |
| **Host risk score** | CLEAN / LOW / MEDIUM / HIGH / CRITICAL — drives node colour in 3D and table badges |
| **CVE lookups per port** | Detected product + version matched against bundled CVE database; results shown in print report with CVSS scores and severity |
| **Security advisories** | Static hints for 20+ ports/services (Redis, SMB, Telnet, RDP…) with severity + tooltip |
| **Version advisories** | Static database of 25+ products (OpenSSH, nginx, Apache, MySQL…) — shows UPDATE or EOL badges next to detected versions |
| **Script results panel** | NSE output shown per-host in HostInspector below the port table |
| **Host notes** | Free-text analyst notes per host, preserved across rescans and exports |
| **Per-port notes** | Inline note textarea per port row — saved to `portNotes` and shown as collapsed hint |
| **Custom host tags** | Add/remove analyst tags per host; first 2 shown as chips in the results table |
| **Port history sparkline** | 64x18 px SVG sparkline of open-port count over the last 10 scans |
| **Workflow status** | DISC → ENUM → TESTED → VULN → MITIG — track pentesting progress per host (reflected in 3D node glow) |
| **PDF report** | `Ctrl+P` or PDF button — executive summary with risk metrics, per-host CVE summary, confidence percentage, and professional print layout |
| **Screenshot** | Capture button saves the full 3D canvas including host labels and port tooltips |
| **Tamper-evident audit log** | HMAC integrity chain — each entry hashes the previous entry's hash using djb2-extended (16-hex-char hashes). Verify button checks chain integrity; tampered or deleted entries detected and flagged |
| **Scan age + staleness** | Relative age per host; amber warning after 10 minutes |

### UI / UX
| Feature | Details |
|---|---|
| **Tabbed panel navigation** | Four tabs — SCAN, HOSTS, INSPECT, LOG — with intelligent auto-switching (inspect on host select, results on scan complete) |
| **Search in results table** | Filter by address, hostname, or service name |
| **Sort by column** | Click ADDRESS, OPEN, AGE, or RISK column headers |
| **Tags column** | First 2 tags shown as chips in results table; click host to add/remove tags |
| **Resizable panel** | Drag the divider between left panel and 3D canvas |
| **3D scene filters** | Collapsible overlay to toggle risk levels (CRIT/HIGH/MED/LOW/OK), host labels, and connection beams |
| **High contrast mode** | WCAG-aware high contrast toggle — adjusts all colours for accessibility |
| **Port family filter** | ALL / WEB / SSH / DB / MAIL / DNS chips dim non-matching port orbs in 3D |
| **Keyboard shortcuts** | `Esc` deselect · `Ctrl+K` focus target · `Ctrl+E` export · `Ctrl+P` PDF · `Del` remove selected host · `Ctrl+1-4` switch tabs |
| **Skip-to-content link** | Accessible skip navigation for keyboard users |
| **Storage error banner** | Amber strip if localStorage quota exceeded — session may not persist |

### 3D Visualization
| Feature | Details |
|---|---|
| **Holographic network observatory** | React Three Fiber scene — hosts, connection beams, service arc rings |
| **Service arc ring** | Always-visible coloured ring around each node divided into arcs by service category (WEB/SSH/DB/MAIL/DNS) — service distribution readable at any camera distance |
| **Host info card** | Clicking a host shows a holographic panel in 3D space listing risk score, service breakdown, workflow status, tags, and scan age — no need to read the left panel |
| **Risk glow floor projection** | Each host projects a coloured disc on the grid below — radius and opacity scale with risk level, creating a spatial threat heatmap across the whole session |
| **Advisory badges** | RISK (red) or warning (amber) floats above hosts with CVE advisories or EOL / outdated versions — visible without clicking |
| **Elevation by attack surface** | Open port count lifts each host's Y position (max ~1.6 units) — high-exposure hosts float higher, creating a readable attack-surface topology |
| **Risk-based node colour + size** | Node colour reflects risk level; more open ports = slightly larger node |
| **Workflow glow** | Vulnerable hosts glow red; mitigated hosts dim to grey in 3D |
| **Subnet clustering + colour palette** | Hosts sharing a /24 subnet are grouped; each subnet gets a distinct colour (cyan/blue/purple/amber/pink) |
| **Depth fog** | Fog fades distant geometry for depth cues |
| **Port orb hover tooltip** | Selected host shows individual orbiting port orbs with hover tooltip (port + service) |
| **Orbit inclination** | Each port's orbit group is tilted slightly (24 degrees) for visual variety |
| **Animated heartbeat ring** | Selected host shows a pulsing outward ring |
| **Discovery flash** | New host nodes fire a brief emissive burst on first appearance |
| **Radar pulse during scan** | Two staggered expanding rings only while scanning |
| **Finalization pulse** | One-shot confirmation ring + connection line surge when XML results arrive |
| **Camera follow** | Selecting a host smoothly shifts the orbit target toward it |
| **Camera presets** | Fit all / Top-down / Reset — bottom-right corner of the 3D view |
| **Label LOD** | Full label (IP + hostname + port count) close-up, IP only mid-range, hidden far away |
| **Provisional nodes** | Dim ghost nodes with service arcs appear live as stdout is parsed during scanning |

---

## Tech stack

| Layer | Technology |
|---|---|
| Desktop shell | [Tauri 2](https://tauri.app/) |
| Frontend | React 19 + TypeScript 5.8 + Vite 7 |
| State management | [Zustand](https://zustand.docs.pmnd.rs/) v5 with `subscribeWithSelector` middleware |
| 3D graphics | Three.js + React Three Fiber + Drei |
| Screenshot | html2canvas (composites WebGL canvas + DOM overlays) |
| Styling | Tailwind CSS 4 + custom CSS variables (cyber dark theme) |
| Backend | Rust (Tokio async via Tauri runtime) |
| Network scanning | [Nmap](https://nmap.org/) (must be installed separately) |
| Testing | Vitest + jsdom + React Testing Library |

---

## Prerequisites

- **Rust** (stable) — [rustup.rs](https://rustup.rs)
- **Node.js** >= 18 + npm
- **Nmap** — [nmap.org/download](https://nmap.org/download.html)
  - Windows: default path `C:\Program Files (x86)\Nmap\` or add to `PATH`
  - Linux/macOS: `apt install nmap` / `brew install nmap`
  - **OS Detect profile** requires administrator / root privileges
  - **UDP Common profile** requires administrator / root privileges

---

## Getting started

```bash
npm install
npm run tauri dev    # development with hot reload
npm run tauri build  # production binary
```

### Running tests

```bash
npm test             # watch mode
npm run test:run     # single run (CI-friendly)
```

---

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Esc` | Deselect host |
| `Ctrl+K` | Focus the target input |
| `Ctrl+E` | Export session to JSON |
| `Ctrl+P` | Print / save PDF report |
| `Del` | Remove the selected host from session |
| `Enter` (in target input) | Start scan |
| `Ctrl+1` | Switch to SCAN tab |
| `Ctrl+2` | Switch to HOSTS tab |
| `Ctrl+3` | Switch to INSPECT tab |
| `Ctrl+4` | Switch to LOG tab |

---

## Scan profiles

| Profile | Flags | Timeout | Notes |
|---|---|---|---|
| Quick | `-sT --top-ports 100 -T4` | 90s | Fast common-port sweep |
| Standard TCP | `-sT -T4` | 600s | Full TCP scan |
| Light Service Detection | `-sT -sV --version-light -T4` | 600s | Service names + versions |
| OS Detect | `-sT -sV -O -T4` | 300s | OS fingerprinting — **requires root/admin** |
| UDP Common | `-sU --top-ports 20 -T4` | 300s | Top 20 UDP ports — **requires root/admin** |

All profiles include `-v --stats-every 1s -oX <tmpfile>` for streaming and XML output.

---

## Security model

- **No shell execution** — nmap is invoked via `std::process::Command::new()` with individual `.arg()` calls. No shell interpolation ever occurs.
- **Content Security Policy** — restrictive CSP in Tauri config: `default-src 'self'`; scripts, styles, images, fonts, and connections locked to `'self'` and required protocols only.
- **Tauri capability denials** — explicit `deny` entries for `fs:default` and `shell:default` in the capabilities config, preventing the webview from accessing filesystem or shell APIs.
- **Input allowlist** — targets validated against a character allowlist (no `;`, `|`, `` ` ``, `$`, newlines, flag prefixes). Port ranges validated against digits/commas/hyphens only.
- **Import sanitisation** — imported host data is sanitised on the frontend: HTML tags stripped, control characters removed, `javascript:` protocol blocked, event handler attributes rejected.
- **Fixed profiles** — the frontend sends a profile name; backend constructs the argument list. Raw nmap flags are never sent from the UI.
- **NSE allowlist** — 8 curated read-only scripts hardcoded in Rust; arbitrary script names from the frontend are rejected.
- **Tamper-evident audit log** — HMAC integrity chain using djb2-extended hashing. Each log entry includes a hash of its content combined with the previous entry's hash. Chain verification detects any tampered or deleted entries.
- **Path-traversal-safe persistence** — Rust session persistence sanitises IDs to alphanumeric, hyphens, and underscores only (max 128 chars), preventing directory traversal attacks.
- **Import validation** — deep schema guard on every imported host entry; malformed entries rejected with a count.
- **Static advisories** — CVE database and version hints are local static tables. AegisMap makes no outbound network requests of its own.
- **44 backend unit tests** — covering validation (14), profiles (10), progress parsing (5), XML parsing (9+).
- **48+ frontend tests** — covering risk scoring, scope validation, audit log integrity, CVE lookups, session diffing, and fingerprint confidence.

---

## Project structure

```
AegisMap/
├── src/
│   ├── App.tsx                      Root layout, tab switching, high contrast, keyboard shortcuts
│   ├── App.css                      Styles including high contrast mode, print layout, accessibility
│   ├── types/index.ts               TypeScript types mirroring Rust models
│   ├── stores/
│   │   ├── scanStore.ts             Zustand store for scan execution state + queue
│   │   ├── sessionStore.ts          Zustand store for session, host merging, persistence
│   │   └── uiStore.ts              Zustand store for UI state (tabs, filters, high contrast)
│   ├── lib/
│   │   ├── riskScore.ts             Host risk scoring from open port advisories
│   │   ├── riskScore.test.ts        10 tests for risk scoring logic
│   │   ├── scopeUtils.ts            CIDR scope validation utilities
│   │   ├── scopeUtils.test.ts       12 tests for scope validation
│   │   ├── auditLog.ts              HMAC integrity chain audit logging
│   │   ├── auditLog.test.ts         8 tests for audit log + chain verification
│   │   ├── sessionDiff.ts           Cross-session diff engine
│   │   ├── sessionDiff.test.ts      9 tests for session diffing
│   │   ├── fingerprint.ts           Confidence scoring + identity extraction
│   │   └── fingerprint.test.ts      7 tests for fingerprint confidence
│   ├── data/
│   │   ├── cveHints.ts              Static security advisory lookup table (20+ ports)
│   │   ├── knownVersions.ts         Static version advisory database (25+ products)
│   │   ├── cveDatabase.ts           Bundled CVE database (12 products, 30+ CVEs, CVSS scores)
│   │   └── cveDatabase.test.ts      10 tests for CVE lookups
│   ├── hooks/
│   │   ├── useProvisionalHosts.ts   Live stdout host discovery during scan
│   │   └── useScanAge.ts            Relative age formatter + staleness flag
│   ├── test/
│   │   └── setup.ts                 Vitest setup (localStorage mock for jsdom)
│   └── components/
│       ├── ScannerPanel.tsx         Controls, profiles, queue, log, exports, import (tabbed)
│       ├── PanelTabs.tsx            Tab navigation bar (SCAN / HOSTS / INSPECT / LOG)
│       ├── SceneFilters.tsx         3D scene filter overlay (risk levels, labels, connections)
│       ├── ResultsTable.tsx         Searchable, sortable host list with risk + tag badges
│       ├── HostInspector.tsx        Port detail, diff, CVE + version advisories, tags, port notes, sparkline
│       ├── AttackSurface.tsx        Session-level risk dashboard
│       ├── NmapStatusBar.tsx        Nmap detection status
│       ├── SessionManager.tsx       Named session save / load / delete (inline UI)
│       ├── ScopeManager.tsx         Authorised range management
│       ├── AuditLog.tsx             Audit log viewer with integrity verification
│       ├── PrintReport.tsx          Print report with executive summary, CVE lookups, confidence scores
│       └── visualization/
│           └── ScanScene.tsx        R3F scene: subnet groups, fog, heartbeat, LOD, presets
│
├── vitest.config.ts                 Vitest configuration (jsdom, aliases, globals)
│
└── src-tauri/src/
    ├── scanner/
    │   ├── validation.rs            Target + port-range + NSE script input validation
    │   ├── profiles.rs              Profile → safe nmap argument lists + per-profile timeouts
    │   ├── executor.rs              Process spawn, watchdog timeout, channel streaming, cancellation
    │   ├── xml_parser.rs            Authoritative XML result parser (handles nmap DOCTYPE)
    │   └── progress.rs              Best-effort progress line parser
    ├── commands/mod.rs              Tauri IPC commands (scan + session persistence)
    ├── models/mod.rs                Rust data models
    ├── persistence.rs               File-based session persistence with path-traversal protection
    └── error.rs                     Serialisable AppError (includes PersistenceError variant)
```

---

## Future capabilities (require additional work)

| Feature | Blocker |
|---|---|
| Scheduled re-scan | Needs persistent background timer management |
| System tray notifications | Needs `tauri-plugin-notification` |
| SQLite scan history | Needs `tauri-plugin-sql` |
| Concurrent scans | Scan store already supports scan-ID-keyed state; needs Rust `HashMap<id, Child>` |
| Live CVE feed | Requires outbound network permission + NVD/OSV API integration |
| Network topology mapping | Traceroute integration for hop-by-hop path visualisation |
| Vulnerability scoring dashboard | Aggregate CVSS scoring across all hosts with trend tracking |
