// ============================================================
// jwtTool.js — JWT decode and security analysis
// ============================================================

import { analyzeJWT }                        from "../analyzers/jwtAnalyzer.js";
import { addFindings, clearFindings }        from "../findings.js";
import { addToHistory }                      from "../history.js";
import { refreshDashboard, registerResetCallback } from "../dashboard.js";
import { renderToolOutput }                  from "../ui.js";


export function initializeJWTTool() {
    const button  = document.getElementById("decodeJwtBtn");
    const inputEl = document.getElementById("jwtInput");

    if (!button || !inputEl) return;

    // Register reset so clearDashboard() clears this input
    registerResetCallback(() => { inputEl.value = ""; });

    button.addEventListener("click", () => handleJWTDecode(inputEl));
}


function handleJWTDecode(inputEl) {
    const token = inputEl.value.trim();

    if (!token) {
        clearFindings();
        refreshDashboard();
        renderToolOutput("JWT Analyzer", { message: "Paste a JWT token to inspect." });
        return;
    }

    clearFindings();

    const result = analyzeJWT(token);

    if (result.error) {
        // Keep findings cleared, show error in output
        refreshDashboard();
        renderToolOutput("JWT Analyzer Error", { error: result.error });
        return;
    }

    renderToolOutput("Decoded JWT", {
        header:  result.header,
        payload: result.payload
    });

    addFindings("JWT Analyzer", result.findings);

    const findings = refreshDashboard();

    addToHistory("JWT Analyzer", token, findings);
}