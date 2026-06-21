// ============================================================
// history.js — Scan history store, rendering, and search
// ============================================================

import { escapeHTML } from "./utils/sanitize.js";

// ---- State ---- (max 20 entries, newest first)
const scanHistory = [];

// ---- Current search query ---- (persists between renders)
let currentQuery = "";


// ============================================================
// Public API
// ============================================================

export function addToHistory(tool, input, findings) {
    const timestamp = new Date().toLocaleTimeString();

    scanHistory.unshift({ tool, input, findings, timestamp });

    if (scanHistory.length > 20) scanHistory.pop();

    renderHistory();
}

export function getHistory() {
    return scanHistory;
}

export function clearHistory() {
    scanHistory.length = 0;
    currentQuery = "";
    clearSearchInput();
    renderHistory();
}

// ============================================================
// Search — called by activityPanel.js on input event
// ============================================================

export function searchHistory(query) {
    currentQuery = query.toLowerCase().trim();
    renderHistory();
}


// ============================================================
// Rendering
// ============================================================

function renderHistory() {
    const container = document.getElementById("history");
    if (!container) return;

    if (scanHistory.length === 0) {
        container.innerHTML = "";   // CSS :empty handles the message
        return;
    }

    // Filter by current query if one exists
    const visible = currentQuery
        ? scanHistory.filter(scan =>
            scan.tool.toLowerCase().includes(currentQuery) ||
            (scan.input || "").toLowerCase().includes(currentQuery)
          )
        : scanHistory;

    if (visible.length === 0) {
        container.innerHTML = `
            <p class="history-empty-search">
                No results for "${escapeHTML(currentQuery)}"
            </p>
        `;
        return;
    }

    container.innerHTML = visible.map(createHistoryCard).join("");
}

function createHistoryCard(scan) {
    const highestSeverity =
        scan.findings.some(f => f.severity === "High")   ? "high"   :
        scan.findings.some(f => f.severity === "Medium") ? "medium" :
        "low";

    // Highlight matching text in tool name and input snippet
    const toolText  = highlight(escapeHTML(scan.tool), currentQuery);
    const inputText = highlight(escapeHTML((scan.input || "").slice(0, 60)), currentQuery);

    return `
        <div class="history-item">
            <div class="history-top">
                <span class="history-time">${scan.timestamp}</span>
                <span class="history-risk ${highestSeverity}">
                    ${scan.findings.length} Findings
                </span>
            </div>
            <div class="history-tool">${toolText}</div>
            <p class="history-input">${inputText}</p>
        </div>
    `;
}

// Wrap matching text in a highlight span — only when a query is active
function highlight(text, query) {
    if (!query) return text;

    // Escape regex special chars in the query
    const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex   = new RegExp(`(${escaped})`, "gi");

    return text.replace(regex, `<mark class="history-highlight">$1</mark>`);
}

// Clear the search input field on full dashboard clear
function clearSearchInput() {
    const input = document.getElementById("historySearch");
    if (input) input.value = "";
}