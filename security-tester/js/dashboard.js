// ============================================================
// dashboard.js — Dashboard state coordination
// ============================================================

import { clearFindings, getFindings } from "./findings.js";
import { renderFindings, updateSummary, renderToolOutput, renderEmptyOutput } from "./ui.js";
import { clearHistory } from "./history.js";

// ---- Reset callbacks registered by each tool ----
// Each initializeTool() registers a function that clears its own input.
// clearDashboard() calls all of them — dashboard never needs to know input IDs.
const resetCallbacks = [];

export function registerResetCallback(fn) {
    resetCallbacks.push(fn);
}


// ============================================================
// Refresh — read store and re-render metrics + findings
// ============================================================

export function refreshDashboard() {
    const findings = getFindings();
    renderFindings(findings);
    updateSummary(findings);
    return findings;
}


// ============================================================
// Full Dashboard Clear
// ============================================================

export function clearDashboard() {
    // Clear each tool's input via registered callbacks
    resetCallbacks.forEach(fn => fn());

    // Clear the findings store and re-render
    clearFindings();
    renderFindings([]);
    updateSummary([]);

    // Clear history
    clearHistory();

    // Reset tool output panel
    renderToolOutput("Security Dashboard", {
        message: "Dashboard cleared successfully."
    });
}