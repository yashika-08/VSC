# 🛡 Sentinel-VSC

**Real-Time Security Guardrail Extension for AI-Assisted Development**

Sentinel-VSC sits between your LLM's output and your editor, ensuring every AI-generated snippet is audited, sanitized, and graded before it enters your codebase.

---

## Features

### 🔴 Real-Time Security Grading
- **CodeLens overlays** appear directly above every vulnerable function with grade (A–F)
- **Status bar indicator** shows live grade with color-coded severity
- **Sidebar panel** with detailed security report, score breakdown, and OWASP coverage

### 🔍 Hybrid Analysis Engine
- **SAST (Static Analysis)**: 33 pattern rules covering OWASP Top 10
  - SQL Injection (A03) — JS/TS, Python, Java, Go, Ruby, PHP
  - XSS / DOM Injection (A03) — JS/TS, Java, Ruby, PHP
  - Broken Authentication / JWT (A07) — JS/TS, Python
  - Path Traversal (A01) — JS/TS, Java
  - Command Injection (A03) — JS/TS, Python, Go, Ruby, PHP
  - Insecure Deserialization (A08) — JS/TS, Python, Java, PHP
  - Security Misconfiguration (A05) — JS/TS, Python, Go
  - SSRF (A10) — JS/TS
  - Sensitive Data Exposure (A02, A09) — JS/TS
- **LLM Security Critic**: Sends code to Claude for deep semantic analysis, catching logic-level vulnerabilities SAST misses

### 🔧 Automated Self-Healing Loops
- **"Fix with Sentinel"** button on every CodeLens and issue
- Sends vulnerable code back to Claude with security constraints
- Shows diff preview before applying
- Automatically re-scans after applying fix

### 🔑 Secret & PII Shield
- Background worker scans before render
- Detects and masks: AWS keys, Stripe keys, GitHub tokens, Slack tokens, JWT secrets, DB passwords, connection strings, SSNs, credit card numbers, PEM private keys
- "Reveal temporarily" option with 30s auto-remask
- Works across JavaScript, TypeScript, Python, Go, Ruby, Java, PHP

---

## Installation

### From VSIX (pre-built)
1. Download `sentinel-vsc-1.0.0.vsix`
2. Open VS Code → Extensions → `...` → Install from VSIX

### From Source
```bash
git clone https://github.com/your-org/sentinel-vsc
cd sentinel-vsc
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

### Build & Package
```bash
npm install -g @vscode/vsce
npm run package
# Produces sentinel-vsc-1.0.0.vsix
```

---

## Configuration

Open Settings (`Cmd+,`) → search "Sentinel":

| Setting | Default | Description |
|---|---|---|
| `sentinel.anthropicApiKey` | `""` | **Required** for LLM Critic. Get key at console.anthropic.com |
| `sentinel.llmModel` | `claude-sonnet-4-20250514` | Anthropic model for the LLM Critic (`claude-sonnet-4-20250514`, `claude-opus-4-20250514`, `claude-haiku-35-20241022`) |
| `sentinel.scanOnSave` | `true` | Auto-scan on file save |
| `sentinel.scanOnType` | `false` | Scan while typing (slower) |
| `sentinel.maskSecrets` | `true` | Mask detected secrets |
| `sentinel.enableSAST` | `true` | Enable static analysis |
| `sentinel.enableLLMCritic` | `true` | Enable Claude-powered critic |
| `sentinel.minimumGradeWarning` | `"C"` | Status bar warning threshold |
| `sentinel.supportedLanguages` | see below | Languages to scan |

**Supported languages** (default): `javascript`, `typescript`, `python`, `java`, `php`, `go`, `ruby`

---

## Usage

| Action | How |
|---|---|
| Scan current file | `Ctrl+Shift+S` / `Cmd+Shift+S` |
| View security panel | Click shield icon in Activity Bar |
| Fix an issue | Click "🔧 Fix with Sentinel" in CodeLens |
| Navigate to issue | Click issue in sidebar tree |
| Reveal masked secret | Hover over masked text → click "Reveal temporarily" |

---

## Architecture

```
sentinel-vsc/
├── src/
│   ├── extension.ts          # Entry point, command registration
│   ├── analysis/
│   │   ├── scanOrchestrator.ts  # Coordinates SAST + LLM + Secret Shield
│   │   ├── sastEngine.ts        # Static analysis rules engine
│   │   ├── llmCritic.ts         # Anthropic API integration
│   │   └── secretShield.ts      # Secret/PII detection & masking
│   ├── providers/
│   │   ├── codeLensProvider.ts  # Inline security overlays
│   │   ├── diagnosticsProvider.ts # VS Code Problems panel
│   │   ├── sidebarProvider.ts   # Webview sidebar
│   │   ├── issuesTreeProvider.ts # Vulnerabilities tree
│   │   └── owaspTreeProvider.ts  # OWASP coverage tree
│   ├── webview/
│   │   └── sidebarHtml.ts       # Sidebar HTML/CSS/JS
│   └── utils/
│       ├── types.ts             # TypeScript interfaces
│       └── statusBar.ts         # Status bar manager
├── test/
│   └── suite/                   # Unit tests
├── package.json                 # Extension manifest
└── tsconfig.json
```

---

## Security Notes

- Your code is sent to Anthropic's API only when `enableLLMCritic` is true and an API key is configured
- Code snippets are truncated to 8,000 characters before sending
- API keys are stored in VS Code's secure settings store
- All network calls use HTTPS

---

## License

MIT © Sentinel-VSC Contributors
