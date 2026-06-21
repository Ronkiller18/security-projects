// ===========================================================
// Scanner Engine
// ===========================================================

// ===========================================================
// State
// ===========================================================

let scanHistory = [];

// ===========================================================
// Elements
// ===========================================================

const scannerElements = {

    requestBox:
        document.getElementById("requestBox"),

    scanStatus:
        document.getElementById("scanStatus"),

    scanSummary:
        document.getElementById("scanSummary"),

    scannerResults:
        document.getElementById("scannerResults"),

    scanHistory:
        document.getElementById("scanHistory"),
    
    clearScanBtn:
        document.getElementById("clearScanBtn")
};

// ===========================================================
// Utilities
// ===========================================================

function getCurrentTime() {

    return new Date().toLocaleTimeString();
}

function updateScanStatus(message) {

    if (scannerElements.scanStatus) {

        scannerElements.scanStatus.textContent =
            message;
    }
}

function createElement(tag, className = "") {

    const element =
        document.createElement(tag);

    if (className) {
        element.className = className;
    }

    return element;
}

// ===========================================================
// Detection Rules Database
// ===========================================================

const detectionRules = {

    xss: [
        {
            regex: /<script[\s\S]*?>/gi,
            label: "<script>",
            dynamic: false
        },

        {
            regex: /on\w+\s*=/gi,
            dynamic: true
        },

        {
            regex: /javascript:/gi,
            label: "javascript:",
            dynamic: false
        }
    ],

    redirect: [
        {
            regex: /redirect\s*=/gi,
            label: "redirect=",
            dynamic: false
        },

        {
            regex: /url\s*=/gi,
            label: "url=",
            dynamic: false
        }
    ],

    dom: [

        {
            regex: /innerHTML\s*=/gi,
            label: "innerHTML",
            dynamic: false
        },

        {
            regex: /document\.write/gi,
            label: "document.write",
            dynamic: false
        },

        {
            regex: /eval\s*\(/gi,
            label: "eval()",
            dynamic: false
        },

        {
            regex: /document\.body\.style/gi,
            label: "document.body.style",
            dynamic: false
        }
    ]
};

// ===========================================================
// Detection Engine
// ===========================================================

function analyzeRequest() {

    const input =
        scannerElements.requestBox?.value.trim();

    if (!input) {

        updateScanStatus("⚪ No input");

        renderResults([]);

        return;
    }

    updateScanStatus("🔍 Scanning...");

    setTimeout(() => {

        const findings = [];

        detectXSS(input, findings);

        detectRedirect(input, findings);

        detectDOMRisk(input, findings);

        renderResults(findings);

        renderSummary(findings);

        // Only save vulnerable scans
        if (findings.length > 0) {

            saveScanToHistory(findings);
        }

        updateScanStatus(
            findings.length > 0
                ? "⚠️ Vulnerabilities Found"
                : "✅ Clean"
        );

    }, 500);
}

// ===========================================================
// Detection Rules
// ===========================================================

function detectXSS(input, findings) {

    const patterns = detectionRules.xss;

    patterns.forEach(pattern => {

        const matches =
            [...input.matchAll(pattern.regex)];

        if (matches.length === 0) return;

        const seenPatterns =
            new Set();

        matches.forEach(match => {

            const matchedPattern =
                pattern.dynamic
                    ? match[0]
                    : pattern.label;

            // Skip duplicate findings
            if (seenPatterns.has(matchedPattern)) {
                return;
            }

            seenPatterns.add(matchedPattern);

            findings.push({

                type: "XSS",

                severity: "High",

                confidence: "High",

                cwe: "CWE-79",

                matchedPattern,

                message:
                    "Script injection pattern detected",

                recommendation:
                    "Avoid rendering untrusted HTML. Use textContent instead."
            });
        });
    });
}

function detectRedirect(input, findings) {

    const patterns = detectionRules.redirect;

    patterns.forEach(pattern => {

        const matches =
            [...input.matchAll(pattern.regex)];

        if (matches.length === 0) return;

        const seenPatterns = new Set();

        matches.forEach(match => {

            const matchedPattern =
                pattern.dynamic
                    ? match[0]
                    : pattern.label;

            // Skip duplicate findings
            if (seenPatterns.has(matchedPattern)) {
                return;
            }

            seenPatterns.add(matchedPattern);

            findings.push({

                type: "Open Redirect",

                severity: "Medium",

                confidence: "Medium",

                cwe: "CWE-601",

                matchedPattern,

                message:
                    "Suspicious redirect parameter",

                recommendation:
                    "Validate redirect destinations against a trusted allowlist."
            });
        });
    });
}

function detectDOMRisk(input, findings) {

    const patterns = detectionRules.dom;

    patterns.forEach(pattern => {

        const matches =
            [...input.matchAll(pattern.regex)];

        if (matches.length === 0) return;

        const seenPatterns = new Set();

        matches.forEach(match => {

            const matchedPattern =
                pattern.dynamic
                    ? match[0]
                    : pattern.label;

            // Skip duplicate findings
            if (seenPatterns.has(matchedPattern)) {
                return;
            }

            seenPatterns.add(matchedPattern);

            findings.push({

                type: "DOM Risk",

                severity: "High",

                confidence: "High",

                cwe: "CWE-79",

                matchedPattern,

                message:
                    "Unsafe DOM manipulation",

                recommendation:
                    "Avoid dangerous DOM APIs like innerHTML and document.write."
            });
        });
    });
}

// ===========================================================
// Render Results
// ===========================================================

function renderResults(findings) {

    const container =
        scannerElements.scannerResults;

    if (!container) return;

    container.innerHTML = "";

    // Empty state
    if (findings.length === 0) {

        const emptyMessage =
            createElement("p", "safe");

        emptyMessage.textContent =
            "✅ No issues detected";

        container.appendChild(emptyMessage);

        return;
    }

    findings.forEach(finding => {

        const card =
            createElement(
                "div",
                `scan-card ${finding.severity.toLowerCase()}`
            );

        const header =
            createElement("div", "scan-header");

        const type =
            createElement("span", "scan-type");

        type.textContent =
            finding.type;

        const severity =
            createElement(
                "span",
                `severity-badge ${finding.severity.toLowerCase()}`
            );

        severity.textContent =
            finding.severity;

        const message =
            createElement("p");

        message.textContent =
            finding.message;

        const confidence =
            createElement("p", "scan-meta");

        confidence.textContent =
            `Confidence: ${finding.confidence}`;

        const cwe =
            createElement("p", "scan-meta");

        cwe.textContent =
            `Reference: ${finding.cwe}`;

        const recommendation =
            createElement("p", "scan-meta");

        recommendation.textContent =
            `Recommendation: ${finding.recommendation}`;

        const toggleBtn =
            createElement(
                "button",
                "scan-toggle"
            );

        toggleBtn.textContent = "Details";

        header.append(
            type,
            severity,
            toggleBtn
        );

        const matched =
            createElement("p", "scan-meta");

        matched.textContent =
            `Matched Pattern: ${finding.matchedPattern}`;

        const details =
            createElement("div", "scan-details");

        details.classList.add("hidden");

        details.append(
            message,
            matched,
            confidence,
            cwe,
            recommendation
        );

        card.append(
            header,
            details
        );

        toggleBtn.addEventListener("click", () => {

            details.classList.toggle("hidden");

            toggleBtn.textContent =
                details.classList.contains("hidden")
                    ? "Details"
                    : "Hide";
        });

        container.appendChild(card);
    });
}

//============================================================
// Render Summary
//============================================================

function renderSummary(findings) {

    const summary =
        scannerElements.scanSummary;

    if (!summary) return;

    // Hide if clean
    if (findings.length === 0) {

        summary.classList.add("hidden");

        summary.innerHTML = "";

        return;
    }

    const highCount =
        findings.filter(
            finding =>
                finding.severity === "High"
        ).length;

    const mediumCount =
        findings.filter(
            finding =>
                finding.severity === "Medium"
        ).length;

    summary.classList.remove("hidden");

    summary.innerHTML = `
        <div class="summary-grid">

            <div class="summary-card">
                <span>Total</span>
                <strong>${findings.length}</strong>
            </div>

            <div class="summary-card">
                <span>High</span>
                <strong>${highCount}</strong>
            </div>

            <div class="summary-card">
                <span>Medium</span>
                <strong>${mediumCount}</strong>
            </div>

        </div>
    `;
}

// ===========================================================
// Scan History
// ===========================================================

function saveScanToHistory(findings) {

    scanHistory.unshift({

        time: getCurrentTime(),

        findings
    });

    renderScanHistory();
}

function renderScanHistory() {

    const container =
        scannerElements.scanHistory;

    if (!container) return;

    container.innerHTML = "";

    // Empty state
    if (scanHistory.length === 0) {

        const placeholder =
            createElement(
                "p",
                "placeholder"
            );

        placeholder.textContent =
            "No scan history yet";

        container.appendChild(placeholder);

        return;
    }

    scanHistory.forEach(scan => {

        const count =
            scan.findings.length;

        const severity =
            scan.findings.some(
                finding =>
                    finding.severity === "High"
            )
                ? "high"
                : "medium";

        const card =
            createElement(
                "div",
                `history-card ${severity}`
            );

        const header =
            createElement(
                "div",
                "history-header"
            );

        const time =
            createElement("span");

        time.textContent =
            scan.time;

        const result =
            createElement("span");

        result.textContent =
            `${count} finding${count !== 1 ? "s" : ""}`;

        header.append(time, result);

        card.appendChild(header);

        container.appendChild(card);
    });
}

// ===========================================================
// Clear Scanner
// ===========================================================

function clearScanner() {

    scanHistory = [];

    // Clear textarea
    if (scannerElements.requestBox) {

        scannerElements.requestBox.value = "";
    }

    // Clear results
    if (scannerElements.scannerResults) {

        scannerElements.scannerResults.innerHTML = "";

        const cleared =
            createElement("p", "placeholder");

        cleared.textContent =
            "Scanner cleared";

        scannerElements.scannerResults.appendChild(
            cleared
        );
    }

    // Clear Summary
    if (scannerElements.scanSummary) {

        scannerElements.scanSummary.classList.add(
            "hidden"
        );

        scannerElements.scanSummary.innerHTML = "";
    }

    // Clear history
    if (scannerElements.scanHistory) {

        scannerElements.scanHistory.innerHTML =
            "<p class='placeholder'>No scan history yet</p>";
    }

    // Reset status
    if (scannerElements.scanStatus) {

        scannerElements.scanStatus.textContent =
            "⚪ Idle";
    }
}

// ===========================================================
// Event Listeners
// ===========================================================

if (scannerElements.clearScanBtn) {

    scannerElements.clearScanBtn.addEventListener(
        "click",
        clearScanner
    );
}

// ===========================================================
// Copy Payload Buttons
// ===========================================================

const copyButtons =
    document.querySelectorAll(".copy-btn");

copyButtons.forEach(button => {

    button.addEventListener("click", () => {

        const payload =
            button.nextElementSibling.textContent;

        navigator.clipboard.writeText(payload);

        button.textContent = "Copied";

        setTimeout(() => {

            button.textContent = "Copy";

        }, 1200);
    });
});