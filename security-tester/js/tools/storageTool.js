// ============================================================
// storageTool.js — Local Storage + Session Storage analyzer
// One tool file handles both tabs — same analyzer, different label
// ============================================================

import { analyzeStorage }                        from "../analyzers/storageAnalyzer.js";
import { clearFindings, addFindings }            from "../findings.js";
import { refreshDashboard, registerResetCallback } from "../dashboard.js";
import { renderToolOutput }                      from "../ui.js";
import { addToHistory }                          from "../history.js";


// ============================================================
// Initialize both tools from one file
// ============================================================

export function initializeStorageTool() {
    initializeSingleStorage({
        buttonId:    "analyzeLocalStorageBtn",
        inputId:     "localStorageInput",
        storageType: "localStorage",
        historyLabel:"Local Storage Analyzer"
    });

    initializeSingleStorage({
        buttonId:    "analyzeSessionStorageBtn",
        inputId:     "sessionStorageInput",
        storageType: "sessionStorage",
        historyLabel:"Session Storage Analyzer"
    });
}


// ============================================================
// Internal — wires up one storage tool panel
// ============================================================

function initializeSingleStorage({ buttonId, inputId, storageType, historyLabel }) {
    const button  = document.getElementById(buttonId);
    const inputEl = document.getElementById(inputId);

    if (!button || !inputEl) return;

    // Register reset so clearDashboard() clears this input
    registerResetCallback(() => { inputEl.value = ""; });

    button.addEventListener("click", () => {
        runStorageAnalysis(inputEl, storageType, historyLabel);
    });
}


// ============================================================
// Analysis runner
// ============================================================

function runStorageAnalysis(inputEl, storageType, historyLabel) {
    const code = inputEl.value.trim();

    if (!code) {
        clearFindings();
        refreshDashboard();
        renderToolOutput(`${storageType} Analyzer`, {
            message: `Paste JavaScript code using ${storageType} to inspect.`
        });
        return;
    }

    clearFindings();

    const findings = analyzeStorage(code, storageType);

    // Count how many setItem / getItem calls were found for the summary
    const setCount = (code.match(/\.setItem\s*\(/gi) || []).length;
    const getCount = (code.match(/\.getItem\s*\(/gi) || []).length;

    renderToolOutput(`${storageType} Analysis Report`, {
        storageType,
        setItemCalls:   setCount,
        getItemCalls:   getCount,
        findingsCount:  findings.length,
        status: findings.length > 0
            ? "Potential client-side storage security issues detected."
            : "No obvious sensitive storage usage detected."
    });

    addFindings(historyLabel, findings);

    const allFindings = refreshDashboard();

    addToHistory(historyLabel, code.slice(0, 80), allFindings);
}