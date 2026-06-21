// ============================================================
// cspTool.js — CSP policy analysis
// ============================================================

import { analyzeCSP }                        from "../analyzers/cspAnalyzer.js";
import { clearFindings, addFindings }        from "../findings.js";
import { refreshDashboard, registerResetCallback } from "../dashboard.js";
import { renderToolOutput }                  from "../ui.js";
import { addToHistory }                      from "../history.js";


export function initializeCSPTool() {
    const button  = document.getElementById("analyzeCspBtn");
    const inputEl = document.getElementById("cspInput");

    if (!button || !inputEl) return;

    // Register reset so clearDashboard() clears this input
    registerResetCallback(() => { inputEl.value = ""; });

    button.addEventListener("click", () => analyzePolicy(inputEl));
}


function analyzePolicy(inputEl) {
    const policy = inputEl.value.trim();

    if (!policy) {
        clearFindings();
        refreshDashboard();
        renderToolOutput("CSP Analyzer", { message: "Paste a CSP policy to inspect." });
        return;
    }

    clearFindings();

    const findings = analyzeCSP(policy);

    renderToolOutput("Parsed CSP Policy", { policy });

    addFindings("CSP Analyzer", findings);

    const allFindings = refreshDashboard();

    addToHistory("CSP Analyzer", policy, allFindings);
}