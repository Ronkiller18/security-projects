// ============================================================
// activityPanel.js — Collapsible panels + findings filter
//                    + history search
// ============================================================

import { searchHistory } from "./history.js";


// ============================================================
// Initialize
// ============================================================

export function initializeActivityPanel() {
    initializeCollapsibles();
    initializeFindingsFilter();
    initializeHistorySearch();
}


// ============================================================
// Collapsible panel headers
// ============================================================

function initializeCollapsibles() {
    const headers = document.querySelectorAll(".collapsible-header");

    headers.forEach(header => {
        const targetId = header.dataset.target;
        const body     = document.getElementById(targetId);
        const icon     = header.querySelector(".collapse-icon");

        if (!body) return;

        header.addEventListener("click", () => {
            const isCollapsed = body.classList.toggle("collapsed");
            if (icon) icon.style.transform = isCollapsed ? "rotate(-90deg)" : "";
        });
    });
}


// ============================================================
// Findings filter bar
// ============================================================

function initializeFindingsFilter() {
    const filterBar = document.querySelector(".findings-filter-bar");
    if (!filterBar) return;

    filterBar.addEventListener("click", e => {
        const btn = e.target.closest(".filter-btn");
        if (!btn) return;

        const filter = btn.dataset.filter;

        // Update active button
        filterBar.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");

        applyFilter(filter);
    });
}


// ============================================================
// Apply filter — shows/hides finding cards by severity class
// ============================================================

export function applyFilter(filter) {
    const results = document.getElementById("results");
    if (!results) return;

    const cards = results.querySelectorAll(".finding-card");

    // Remove any existing empty state message
    const existing = results.querySelector(".filter-empty-state");
    if (existing) existing.remove();

    let visibleCount = 0;

    cards.forEach(card => {
        if (filter === "all") {
            card.classList.remove("filter-hidden");
            visibleCount++;
        } else {
            // card has class "severity-high", "severity-medium", or "severity-low"
            const matches = card.classList.contains(`severity-${filter}`);
            card.classList.toggle("filter-hidden", !matches);
            if (matches) visibleCount++;
        }
    });

    // Show empty state if filter yields no results
    if (cards.length > 0 && visibleCount === 0) {
        const msg = document.createElement("p");
        msg.className = "filter-empty-state";
        msg.textContent = `No ${filter} severity findings.`;
        results.appendChild(msg);
    }
}


// ============================================================
// Reset filter to "All" — called by ui.js after re-render
// ============================================================

export function resetFilter() {
    const filterBar = document.querySelector(".findings-filter-bar");
    if (!filterBar) return;

    filterBar.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    const allBtn = filterBar.querySelector("[data-filter='all']");
    if (allBtn) allBtn.classList.add("active");
}


// ============================================================
// History search input wiring
// ============================================================

function initializeHistorySearch() {
    const input = document.getElementById("historySearch");
    if (!input) return;

    // Search on every keystroke — instant filtering
    input.addEventListener("input", () => {
        searchHistory(input.value);
    });

    // Clear on Escape key
    input.addEventListener("keydown", e => {
        if (e.key === "Escape") {
            input.value = "";
            searchHistory("");
        }
    });
}