// ============================================================
// ui.js — DOM rendering for findings, summary, tool output
// ============================================================

import { escapeHTML }  from "./utils/sanitize.js";
import { resetFilter } from "./activityPanel.js";


// ============================================================
// Findings Rendering
// ============================================================

export function renderFindings(findings) {
    const container = document.getElementById("results");
    if (!container) return;

    if (findings.length === 0) {
        container.innerHTML = "";   // CSS :empty handles the empty message
        resetFilter();              // reset filter buttons to "All"
        return;
    }

    container.innerHTML = findings.map(createFindingCard).join("");
    resetFilter();                  // new scan always starts showing all findings
}


// ============================================================
// Summary / Metrics + Severity Chart
// ============================================================

export function updateSummary(findings) {
    const findingCount = document.getElementById("findingCount");
    const highCount    = document.getElementById("highCount");
    const riskScore    = document.getElementById("riskScore");
    const findingLabel = document.getElementById("findingLabel");

    if (!findingCount || !highCount || !riskScore || !findingLabel) return;

    const high   = findings.filter(f => f.severity === "High").length;
    const medium = findings.filter(f => f.severity === "Medium").length;
    const low    = findings.filter(f => f.severity === "Low").length;
    const total  = findings.length;
    const score  = calculateRiskScore(findings);

    findingCount.textContent = total;
    findingLabel.textContent = `${total} Active`;
    highCount.textContent    = high;
    riskScore.textContent    = score;

    updateChart(high, medium, low, total);
}

function updateChart(high, medium, low, total) {
    const chart     = document.getElementById("severityChart");
    const barHigh   = document.getElementById("barHigh");
    const barMedium = document.getElementById("barMedium");
    const barLow    = document.getElementById("barLow");
    const countHigh   = document.getElementById("countHigh");
    const countMedium = document.getElementById("countMedium");
    const countLow    = document.getElementById("countLow");

    if (!chart || !barHigh || !barMedium || !barLow) return;

    if (total === 0) {
        // Hide chart when no findings
        chart.classList.remove("severity-chart--visible");
        barHigh.style.width   = "0%";
        barMedium.style.width = "0%";
        barLow.style.width    = "0%";
        return;
    }

    // Show chart
    chart.classList.add("severity-chart--visible");

    // Bars are relative to the highest count so the
    // dominant severity always fills the track fully
    const max = Math.max(high, medium, low, 1);

    barHigh.style.width   = `${(high   / max) * 100}%`;
    barMedium.style.width = `${(medium / max) * 100}%`;
    barLow.style.width    = `${(low    / max) * 100}%`;

    if (countHigh)   countHigh.textContent   = high;
    if (countMedium) countMedium.textContent = medium;
    if (countLow)    countLow.textContent    = low;
}


// ============================================================
// Tool Output
// ============================================================

export function renderToolOutput(title, data) {
    const container = document.getElementById("toolOutput");
    if (!container) return;

    container.innerHTML = `
        <div class="tool-output-card">
            <div class="tool-output-header">
                <h4>${escapeHTML(title)}</h4>
            </div>
            <pre class="tool-output-content">${escapeHTML(JSON.stringify(data, null, 2))}</pre>
        </div>
    `;
}

export function renderEmptyOutput() {
    const container = document.getElementById("toolOutput");
    if (!container) return;
    container.innerHTML = `<p class="empty-state">Run a tool to view analysis output.</p>`;
}


// ============================================================
// Finding Card
// ============================================================

function createFindingCard(finding) {
    const severity = finding.severity.toLowerCase(); // "high" | "medium" | "low"

    return `
        <article class="finding-card severity-${severity}">

            <div class="finding-card-header">
                <span class="finding-title">${escapeHTML(finding.type)}</span>
                <span class="badge badge-${severity}">${escapeHTML(finding.severity)}</span>
            </div>

            <div class="finding-source">${escapeHTML(finding.source || "Analyzer")}</div>

            <p class="finding-description">${escapeHTML(finding.description)}</p>

            <p class="finding-confidence">Confidence: ${finding.confidence}%</p>

            <p class="finding-recommendation">
                <strong>Recommendation:</strong> ${escapeHTML(finding.recommendation)}
            </p>

            ${createPayloadList(finding.payloads)}

        </article>
    `;
}


// ============================================================
// Payload List
// ============================================================

function createPayloadList(payloads) {
    if (!payloads || payloads.length === 0) return "";

    return `
        <ul class="payload-list">
            ${payloads.map(p => `<li>${escapeHTML(p)}</li>`).join("")}
        </ul>
    `;
}


// ============================================================
// Risk Score Calculator
// ============================================================

function calculateRiskScore(findings) {
    return findings.reduce((score, finding) => {
        switch (finding.severity) {
            case "High":   return score + 40;
            case "Medium": return score + 20;
            case "Low":    return score + 10;
            default:       return score;
        }
    }, 0);
}