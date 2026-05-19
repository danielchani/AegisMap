# AegisMap — Security Model

## Threat Model

| # | Threat | Vector | Impact |
|---|--------|--------|--------|
| T1 | Command injection via target input | Malicious string passed as Nmap target | Arbitrary command execution on host |
| T2 | Argument injection via profile bypass | Frontend sends extra flags | Unintended Nmap capabilities (sudo, NSE, UDP) |
| T3 | Massive scan via broad CIDR | User enters /0 or /8 target | Thousands of packets sent; potential legal/network risk |
| T4 | Privilege escalation | App runs sudo/pkexec automatically | Root-level access without user consent |
| T5 | XSS via log/result data | Malicious Nmap output rendered in UI | UI spoofing or script execution |
| T6 | Unrestricted filesystem access | Frontend reads/writes arbitrary paths | Credential theft, data exfiltration |
| T7 | Path traversal in session persistence | Attacker-controlled session ID | Read/write files outside sessions directory |

---

## Mitigations

### T1 — Command injection
- Nmap is executed via `std::process::Command::new("nmap").args(vec)` — **never** a shell string.
- The target is passed as a single positional element in the args vector.
- `validate_target()` in `scanner/validation.rs` enforces a strict character allowlist
  (`a-z A-Z 0-9 . - : / [ ] *`) and rejects newlines, semicolons, pipes, backticks, dollar signs,
  and dash-prefixed strings.

### T2 — Argument injection
- The frontend sends only a `ScanProfile` enum variant and optional validated fields.
- The backend maps the enum to a **fixed, hardcoded** `Vec<&str>`; no user-controlled
  element enters the argument vector.
- No endpoint accepts raw Nmap flag strings.

### T3 — Broad CIDR scans
- `validate_cidr_scope()` in `scanner/validation.rs` is called before any scan starts.
- **IPv4**: rejects any CIDR broader than `/20` (more than 4 096 hosts).
- **IPv6**: rejects any CIDR broader than `/48`.
- Error is returned immediately — nmap is never spawned for an out-of-scope CIDR.

### T4 — Privilege escalation
- The app never calls `sudo`, `pkexec`, `runas`, or equivalent.
- `preflight::check_profile_privileges()` in `scanner/preflight.rs` detects whether the selected
  profile requires raw-socket access and whether the current process has it.
- If privileges are insufficient, a clear error is returned **before** nmap spawns —
  the user sees an actionable message, not a raw exit-code failure.
- Privilege requirements per profile:
  | Profile | Requires elevation? | Reason |
  |---------|-------------------|--------|
  | Quick, TCP, Service | No | TCP connect scan, no raw sockets |
  | OS Detect | Yes | Raw IP socket for OS fingerprinting |
  | UDP Common | Yes | Raw socket for UDP |
  | Stealth SYN | Yes | Half-open; raw socket for SYN-only packets |
  | ACK Probe | Yes | Raw socket for ACK-only packets |
  | Evasion Scan | Yes | Raw socket + fragmented packets + decoys |

### T5 — Log/result rendering
- Log lines are rendered as plain text, not as HTML.
- React escapes text content by default; no `dangerouslySetInnerHTML` is used in the app.
- Result table cells come from parsed structs, not raw Nmap output injected into the DOM.
- Input sanitisation in `ScannerPanel.tsx` strips HTML tags, control characters, `javascript:`
  protocol strings, and event-handler attributes from any imported host data.

### T6 — Filesystem access
- The Tauri capability file (`capabilities/default.json`) explicitly **denies** `fs:default`
  and `shell:default`.
- The frontend has no filesystem access at all; only the Rust backend can read/write files.
- The Nmap XML output is written to `std::env::temp_dir()` with a timestamped name and
  deleted immediately after parsing.

### T7 — Session path traversal
- Session IDs are sanitised in `persistence.rs` by filtering to alphanumeric, `-`, `_` only,
  then capped at 128 characters before being used to construct a file path.
- The sessions directory is resolved via `tauri::Manager::path().app_data_dir()` — always
  inside the platform app-data directory, not user-controlled.

---

## Content Security Policy

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:;
font-src 'self' data:;
connect-src 'self' ipc: http://ipc.localhost;
worker-src 'self' blob:
```

Notes:
- `script-src 'self'` — **no `'unsafe-inline'`**. Vite bundles all JS into files; no inline
  scripts are used at runtime. Blocks eval-based and injection-based XSS attacks.
- `style-src 'self' 'unsafe-inline'` — `'unsafe-inline'` is retained for styles because
  shadcn/ui and Three.js inject `<style>` tags at runtime.
- `connect-src` restricts all network connections to IPC only; no external URLs are reachable
  from the frontend JavaScript context.
- `blob:` in `img-src` and `worker-src` is required for Three.js texture loading.

---

## Tauri Capability Grants

Defined in `src-tauri/capabilities/default.json`:

```json
{
  "permissions": ["core:default", "opener:default"],
  "deny": ["fs:default", "shell:default"]
}
```

Only two plugins are granted:
- `core:default` — basic window management (resize, close, move)
- `opener:default` — open external URLs in the system browser (used for error-page links)

Explicitly denied (belt-and-suspenders over the default-deny posture):
- `fs:default` — no frontend filesystem access
- `shell:default` — no shell execution from JavaScript

---

## Items Intentionally Excluded from All Profiles

| Blocked feature | Reason |
|----------------|---------|
| Free-form Nmap flag input | Direct command injection path |
| `--script` / NSE (non-allowlisted) | Arbitrary code execution via scripts |
| `-sU` outside UdpCommon profile | Avoided unless explicitly chosen |
| Version intensity above 3 (`--version-intensity`) | Excessive probe traffic |
| `--min-rate` / `--max-rate` | Flood risk on large targets |
| `-iL` (input file) | Filesystem access outside intended scope |
| `--script-args` | NSE dependency; not needed for allowlisted scripts |
| T5 timing (`-T5`) | Extremely aggressive; excluded via `validate_timing()` |
