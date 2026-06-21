// ============================================================
// headerTool.js — Security Header Analyzer tool
// Follows the exact same pattern as cspTool.js
// ============================================================

import { analyzeHeaders }                        from "../analyzers/headerAnalyzer.js";
import { clearFindings, addFindings }            from "../findings.js";
import { refreshDashboard, registerResetCallback } from "../dashboard.js";
import { renderToolOutput }                      from "../ui.js";
import { addToHistory }                          from "../history.js";


export function initializeHeaderTool() {
    const button  = document.getElementById("analyzeHeaderBtn");
    const inputEl = document.getElementById("headerInput");

    if (!button || !inputEl) return;

    // Register reset so clearDashboard() clears this input
    registerResetCallback(() => { inputEl.value = ""; });

    button.addEventListener("click", () => analyzeHeaderInput(inputEl));
}


function analyzeHeaderInput(inputEl) {
    const raw = inputEl.value.trim();

    if (!raw) {
        clearFindings();
        refreshDashboard();
        renderToolOutput("Header Analyzer", {
            message: "Paste HTTP response headers to inspect."
        });
        return;
    }

    clearFindings();

    const findings = analyzeHeaders(raw);

    // Build a parsed summary for the output panel
    const lines   = raw.split("\n").filter(l => l.includes(":"));
    const parsed  = {};
    lines.forEach(line => {
        const colonIndex = line.indexOf(":");
        if (colonIndex === -1) return;
        const name  = line.slice(0, colonIndex).trim();
        const value = line.slice(colonIndex + 1).trim();
        parsed[name] = value;
    });

    renderToolOutput("Security Header Report", {
        headersDetected: Object.keys(parsed).length,
        headers: parsed
    });

    addFindings("Header Analyzer", findings);

    const allFindings = refreshDashboard();

    addToHistory("Header Analyzer", raw.slice(0, 80), allFindings);
}