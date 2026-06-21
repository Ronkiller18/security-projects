# Client-Side Security Tester

**Version: 1.4**
Educational browser-based security analysis platform. No build tools, no dependencies, no server required. Open `index.html` directly in any modern browser.

---

## Project Structure

```
security-tester/
│
├── index.html                  — Main dashboard
├── learn.html                  — Documentation page
│
├── css/
│   ├── global.css              — Variables, reset, header, footer, shared panels, buttons
│   ├── dashboard.css           — Two-column grid, workspace, tool tabs, output, metrics, chart
│   ├── findings.css            — Finding cards, badges, history items, filter bar, search bar
│   └── learn.css               — Documentation layout, sidebar TOC, code blocks, copy buttons
│
├── js/
│   ├── main.js                 — App bootstrap, DOMContentLoaded, button wiring
│   ├── toolManager.js          — Tab switching between tool panels
│   ├── dashboard.js            — State coordination, reset callback registry, clear
│   ├── findings.js             — In-memory findings store (add, get, clear)
│   ├── history.js              — Scan history store, rendering, search
│   ├── activityPanel.js        — Collapsible panels, findings filter, history search wiring
│   ├── ui.js                   — DOM rendering: findings cards, summary, chart, tool output
│   ├── export.js               — JSON export + HTML report generation
│   ├── learn.js                — Documentation page: copy buttons, TOC scroll tracking
│   │
│   ├── tools/                  — One file per tool panel (UI wiring only, no detection logic)
│   │   ├── scannerTool.js      — Security Scanner (XSS + DOM + Phishing)
│   │   ├── jwtTool.js          — JWT Analyzer
│   │   ├── cspTool.js          — CSP Analyzer
│   │   ├── headerTool.js       — Security Header Analyzer
│   │   ├── cookieTool.js       — Cookie Security Analyzer
│   │   └── storageTool.js      — Local Storage + Session Storage Analyzer
│   │
│   ├── analyzers/              — Pure detection logic, no DOM access, return Finding[]
│   │   ├── xssAnalyzer.js      — XSS pattern detection
│   │   ├── domAnalyzer.js      — DOM sink detection
│   │   ├── phishingAnalyzer.js — URL reputation + phishing detection
│   │   ├── jwtAnalyzer.js      — JWT decode + security checks
│   │   ├── cspAnalyzer.js      — CSP directive analysis
│   │   ├── headerAnalyzer.js   — HTTP security header analysis
│   │   ├── cookieAnalyzer.js   — Set-Cookie attribute analysis
│   │   └── storageAnalyzer.js  — localStorage/sessionStorage code analysis
│   │
│   └── utils/
│       ├── sanitize.js         — escapeHTML() — used everywhere before rendering
│       └── createFinding.js    — Finding factory — single source of finding shape
│
└── README.md
```

---

## Architecture — How Everything Connects

```
User clicks analyze button
        │
        ▼
   [tool/*.js]
   - reads input from DOM
   - calls clearFindings()
   - calls analyzer(input) → Finding[]
   - calls addFindings(source, results)
   - calls renderToolOutput(title, data)
   - calls refreshDashboard()
   - calls addToHistory(tool, input, findings)
        │
        ▼
   [findings.js]              [ui.js]                [history.js]
   in-memory store    →   renders finding cards   renders history items
                      →   updates metric numbers
                      →   updates severity chart
```

### The Finding Shape

Every finding in the system is created by `createFinding()` in `utils/createFinding.js`:

```javascript
{
    type:           string,   // short name shown as card title
    severity:       string,   // "High" | "Medium" | "Low" — validated, no other values accepted
    description:    string,   // one paragraph explanation
    recommendation: string,   // one paragraph fix
    confidence:     number,   // 0–100, default 100
    payloads:       string[], // optional example strings, default []
    source:         string    // set by addFindings(), overrides factory default
}
```

Severity must be exactly `"High"`, `"Medium"`, or `"Low"`. Any other value triggers a console warning and defaults to `"Low"`.

### Risk Score

```
High   = +40 points per finding
Medium = +20 points per finding
Low    = +10 points per finding
```

Calculated in `ui.js` `calculateRiskScore()`. Used by metrics panel and HTML export.

---

## CSS Architecture

### Variables — all in `global.css` `:root`

```css
--bg-base, --bg-panel, --bg-panel-alt, --bg-hover   /* backgrounds */
--border, --border-light                             /* borders */
--text-primary, --text-secondary, --text-muted       /* text */
--accent, --accent-dim, --accent-glow                /* blue accent */
--risk-high, --risk-high-bg                          /* red */
--risk-medium, --risk-medium-bg                      /* amber */
--risk-low, --risk-low-bg                            /* green */
--font-ui, --font-mono                               /* typography */
--radius-sm, --radius, --radius-lg                   /* border radius */
--transition                                         /* 0.18s ease */
--tool-output-height                                 /* 280px — change to resize output panel */
```

### CSS Class Conventions

Finding cards rendered by `ui.js`:
```
.finding-card.severity-high
.finding-card.severity-medium
.finding-card.severity-low
```

Severity badges:
```
.badge.badge-high
.badge.badge-medium
.badge.badge-low
```

History risk badges:
```
.history-risk.high
.history-risk.medium
.history-risk.low
```

These class names are a contract between `ui.js`/`history.js` and `findings.css`. If you rename them in one place, rename them in both.

---

## How to Add a New Tool — Complete Checklist

### Step 1 — Create the analyzer `js/analyzers/myAnalyzer.js`

```javascript
import { createFinding } from "../utils/createFinding.js";

export function analyzeMyThing(input) {
    const findings = [];

    // Always return an array — never null, never a single object
    if (!looksRelevant(input)) return [];

    if (someCondition) {
        findings.push(createFinding({
            type:           "Finding Name",
            severity:       "High",          // "High" | "Medium" | "Low" only
            confidence:     85,
            description:    "What is wrong.",
            recommendation: "How to fix it.",
            payloads:       ["example1", "example2"]  // optional
        }));
    }

    return findings;
}
```

Rules for analyzers:
- No DOM access — pure functions only
- Always return `Finding[]` — empty array means no findings
- Each check is independent — push its own finding, do not combine
- Use `createFinding()` for every finding — never construct the object manually

### Step 2 — Create the tool `js/tools/myTool.js`

```javascript
import { analyzeMyThing }                        from "../analyzers/myAnalyzer.js";
import { clearFindings, addFindings }            from "../findings.js";
import { refreshDashboard, registerResetCallback } from "../dashboard.js";
import { renderToolOutput }                      from "../ui.js";
import { addToHistory }                          from "../history.js";

export function initializeMyTool() {
    const button  = document.getElementById("analyzeMyBtn");
    const inputEl = document.getElementById("myInput");

    if (!button || !inputEl) return;

    registerResetCallback(() => { inputEl.value = ""; });

    button.addEventListener("click", () => runMyAnalysis(inputEl));
}

function runMyAnalysis(inputEl) {
    const input = inputEl.value.trim();

    if (!input) {
        clearFindings();
        refreshDashboard();
        renderToolOutput("My Analyzer", { message: "Paste something to inspect." });
        return;
    }

    clearFindings(); // each tool run starts fresh

    const findings = analyzeMyThing(input);

    renderToolOutput("My Analysis Report", {
        findingsCount: findings.length,
        status: findings.length > 0 ? "Issues detected." : "No issues detected."
    });

    addFindings("My Analyzer", findings);

    const allFindings = refreshDashboard();

    addToHistory("My Analyzer", input.slice(0, 80), allFindings);
}
```

### Step 3 — Add tab button to `index.html`

Inside `.tool-navigation` nav, before the `<!-- Add new tool tabs here -->` comment:

```html
<button class="tool-tab" data-tool="mytool" role="tab" aria-selected="false">My Tool</button>
```

### Step 4 — Add workspace to `index.html`

After the last `</section>` closing tag of the previous tool workspace:

```html
<section class="tool-workspace" data-tool-panel="mytool" role="tabpanel">
    <div class="tool-header">
        <h2>My Tool Name</h2>
        <p>One sentence description.</p>
    </div>
    <div class="tool-content">
        <label for="myInput">Input Label</label>
        <textarea id="myInput" class="tool-textarea" placeholder="Paste something..."></textarea>
        <div class="action-row">
            <button id="analyzeMyBtn">Analyze</button>
        </div>
    </div>
</section>
```

The `data-tool` on the tab button and `data-tool-panel` on the workspace must match exactly. `toolManager.js` handles everything else automatically.

### Step 5 — Wire in `main.js`

```javascript
import { initializeMyTool } from "./tools/myTool.js";

// inside DOMContentLoaded:
initializeMyTool();
```

That is the complete process. No other files need to change.

---

## Key Decisions and Why

**No frameworks, no build step** — the project runs by opening `index.html`. ES modules (`type="module"`) handle imports natively in all modern browsers. Adding a bundler would contradict the educational, zero-dependency goal.

**Each tool run calls `clearFindings()` first** — findings from one tool do not accumulate alongside findings from another tool. This is intentional and documented in each tool file. If you ever want findings to persist across tools, remove `clearFindings()` from the tools and only call it in `clearDashboard()`.

**`registerResetCallback()` in `dashboard.js`** — each tool registers its own input clear function. `clearDashboard()` calls all of them. This means `dashboard.js` never needs to know any input element IDs. Adding a new tool just requires calling `registerResetCallback()` in its `initialize` function.

**Analyzers return arrays, never null** — `scannerTool.js` iterates over results from multiple analyzers. Every analyzer must return `[]` for no match. Returning `null` or a single object breaks the iteration pattern.

**`escapeHTML()` on everything before rendering** — all user input displayed in the DOM goes through `escapeHTML()` from `utils/sanitize.js`. The function handles `null`, `undefined`, numbers, and booleans safely via `String(str)` coercion.

**Severity chart bars are relative, not percentage-of-total** — `ui.js` sets bar widths relative to the highest count. This means the dominant severity always fills its track. A result of `High: 1, Medium: 0, Low: 0` shows a full red bar, not a tiny sliver.

**`tool-output-height` CSS variable** — the tool output panel fixed height is controlled by a single variable in `global.css`. Change `--tool-output-height: 280px` to resize it everywhere.

---

## Current Tools and What They Accept

| Tool | Input | Analyzer |
|---|---|---|
| Security Scanner | URL, JS snippet, HTML payload | xssAnalyzer, domAnalyzer, phishingAnalyzer |
| JWT Analyzer | Raw JWT string (three dot-separated segments) | jwtAnalyzer |
| CSP Analyzer | Raw CSP header value | cspAnalyzer |
| Header Analyzer | Raw HTTP response headers (one per line) | headerAnalyzer |
| Cookie Analyzer | Set-Cookie header lines | cookieAnalyzer |
| Local Storage | JavaScript code using localStorage | storageAnalyzer |
| Session Storage | JavaScript code using sessionStorage | storageAnalyzer |

---

## Current Analyzer Detection Coverage

### XSS (`xssAnalyzer.js`)
`<script>` tags, inline event handlers (`on*=`), `onerror=`, `onload=`, `javascript:` protocol, `<iframe src=`

### DOM Sinks (`domAnalyzer.js`)
`innerHTML=`, `outerHTML=`, `document.write()`, `insertAdjacentHTML()`, `eval()`, `location.href=`, `location.assign()`, `location.replace()`

### URL Reputation (`phishingAnalyzer.js`)
Raw IP as domain, excessive subdomain depth (3+), brand keyword + suspicious TLD, action keywords + suspicious TLD (score threshold ≥ 2), URL-encoded characters in hostname, homograph/IDN lookalike characters

### JWT (`jwtAnalyzer.js`)
`alg: none` (case-insensitive), missing `exp` claim, sensitive key names in payload (`password`, `secret`, `apikey`, `api_key`, `tokensecret`, `passwd`)

### CSP (`cspAnalyzer.js`)
`unsafe-inline`, `unsafe-eval`, wildcard `script-src` (regex — catches spacing variants), wildcard `object-src`, missing `frame-ancestors`

### Security Headers (`headerAnalyzer.js`)
Missing/present: CSP, HSTS (+ max-age strength + includeSubDomains), X-Frame-Options (+ valid value check), X-Content-Type-Options (+ nosniff check), Referrer-Policy (+ strong value check), Permissions-Policy, X-XSS-Protection misconfiguration, Cache-Control on sensitive pages

### Cookies (`cookieAnalyzer.js`)
Per cookie: missing HttpOnly, missing Secure, missing SameSite, SameSite=None without Secure, SameSite=None present, sensitive name + both flags missing, no expiry. Sensitive name detection: `session`, `token`, `auth`, `jwt`, `user`, `admin`, `id`, `key`, `secret`, `pass`, `cred`

### Storage (`storageAnalyzer.js`)
Sensitive key names in `setItem`, JWT value pattern in code, Bearer token pattern, `JSON.stringify` inside `setItem`, sensitive key names in `getItem`, `eval()` with storage value, general usage notice (fallback Low)

---

## Planned / Roadmap

```
Version 1.1  Security Header Analyzer      ✅ Done
             Cookie Analyzer               ✅ Done
Version 1.2  Local Storage Analyzer        ✅ Done
             Session Storage Analyzer      ✅ Done
Version 1.3  HTML Security Report Export   ✅ Done
Version 1.4  Findings filtering            ✅ Done
             History search               ✅ Done
             Risk severity chart          ✅ Done

Next:
- URL Reputation: WHOIS/DNS lookup integration (requires API or backend)
- Findings persistence: localStorage to survive page refresh
- learn.html: add documentation sections for new tools
- Clipboard API fallback for older browsers (copy buttons)
- Keyboard navigation for tool tabs (arrow keys, Enter)
```

---

## Context for Resuming Development

When resuming work on this project in a new session, share this README and state which version or feature you are working on. The minimum context needed to continue is:

1. This README
2. The specific file(s) being changed
3. What the new feature should do

The architecture is consistent enough that any new tool can be built by following the checklist above without needing to read every existing file first.