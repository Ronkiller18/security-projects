// ============================================================
// scannerTool.js — Security Scanner (XSS + DOM + Phishing)
// ============================================================

import { detectXSS }      from "../analyzers/xssAnalyzer.js";
import { detectDOMRisk }  from "../analyzers/domAnalyzer.js";
import { detectPhishing } from "../analyzers/phishingAnalyzer.js";
import { clearFindings, addFindings } from "../findings.js";
import { refreshDashboard }           from "../dashboard.js";
import { renderToolOutput }           from "../ui.js";
import { addToHistory }               from "../history.js";
import { registerResetCallback }      from "../dashboard.js";


export function initializeScannerTool() {
    const button  = document.getElementById("analyzeBtn");
    const inputEl = document.getElementById("inputData");

    if (!button || !inputEl) return;

    // Register reset callback so clearDashboard() can clear this input
    registerResetCallback(() => { inputEl.value = ""; });

    button.addEventListener("click", () => runAnalysis(inputEl));
}


function runAnalysis(inputEl) {
    const input = inputEl.value.trim();
    if (!input) return;

    // Each tool run starts fresh — clears previous tool's findings
    clearFindings();

    const analyzers = [
        { name: "XSS Analyzer",      handler: detectXSS      },
        { name: "DOM Analyzer",       handler: detectDOMRisk  },
        { name: "Phishing Analyzer",  handler: detectPhishing }
    ];

    const triggeredAnalyzers = [];

    analyzers.forEach(analyzer => {
        // Analyzers return an array (empty = no findings)
        const results = analyzer.handler(input);
        if (!results || results.length === 0) return;

        triggeredAnalyzers.push(analyzer.name);
        addFindings(analyzer.name, results);
    });

    const findings = refreshDashboard();

    renderToolOutput("Security Scanner Report", {
        analyzersExecuted:  analyzers.map(a => a.name),   // derived, never hardcoded
        analyzersTriggered: triggeredAnalyzers,
        findingsDetected:   findings.length,
        highRiskFindings:   findings.filter(f => f.severity === "High").length,
        status: findings.length > 0
            ? "Potential client-side security issues detected."
            : "No obvious threats detected."
    });

    addToHistory("Security Scanner", input, findings);
}