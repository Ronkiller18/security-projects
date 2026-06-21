// ============================================================
// export.js — JSON report export
// ============================================================

import { getFindings } from "./findings.js";
import { renderToolOutput } from "./ui.js";


export function initializeExport() {
    const button = document.getElementById("exportBtn");
    if (!button) return;
    button.addEventListener("click", exportResults);
}


export function exportResults() {
    const findings = getFindings();

    if (findings.length === 0) {
        // Inline message instead of alert()
        renderToolOutput("Export", {
            status:  "No findings to export.",
            message: "Run an analysis first, then export the results."
        });
        return;
    }

    const report = {
        exportedAt:    new Date().toISOString(),
        totalFindings: findings.length,
        findings
    };

    downloadJSON(report, createFileName());
}


// ---- Helpers ----

function downloadJSON(data, filename) {
    const blob = new Blob(
        [JSON.stringify(data, null, 2)],
        { type: "application/json" }
    );

    const url  = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href     = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
}

function createFileName() {
    const timestamp = new Date().toISOString().replace(/:/g, "-");
    return `security-report-${timestamp}.json`;
}