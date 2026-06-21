// ============================================================
// cookieTool.js — Cookie Security Analyzer tool
// Follows the exact same pattern as headerTool.js
// ============================================================

import { analyzeCookies }                        from "../analyzers/cookieAnalyzer.js";
import { clearFindings, addFindings }            from "../findings.js";
import { refreshDashboard, registerResetCallback } from "../dashboard.js";
import { renderToolOutput }                      from "../ui.js";
import { addToHistory }                          from "../history.js";


export function initializeCookieTool() {
    const button  = document.getElementById("analyzeCookieBtn");
    const inputEl = document.getElementById("cookieInput");

    if (!button || !inputEl) return;

    registerResetCallback(() => { inputEl.value = ""; });

    button.addEventListener("click", () => analyzeCookieInput(inputEl));
}


function analyzeCookieInput(inputEl) {
    const raw = inputEl.value.trim();

    if (!raw) {
        clearFindings();
        refreshDashboard();
        renderToolOutput("Cookie Analyzer", {
            message: "Paste Set-Cookie headers to inspect."
        });
        return;
    }

    clearFindings();

    const findings = analyzeCookies(raw);

    // Build summary for tool output panel
    const cookieLines = raw
        .split("\n")
        .filter(l => l.trim().length > 0);

    // Extract cookie names for the summary
    const cookieNames = cookieLines.map(line => {
        const cleaned = line.replace(/^set-cookie:\s*/i, "").trim();
        const nameVal = cleaned.split(";")[0];
        const eqIdx   = nameVal.indexOf("=");
        return eqIdx !== -1 ? nameVal.slice(0, eqIdx).trim() : nameVal.trim();
    }).filter(Boolean);

    renderToolOutput("Cookie Security Report", {
        cookiesAnalyzed: cookieNames.length,
        cookiesFound:    cookieNames,
        findingsCount:   findings.length
    });

    addFindings("Cookie Analyzer", findings);

    const allFindings = refreshDashboard();

    addToHistory("Cookie Analyzer", raw.slice(0, 80), allFindings);
}