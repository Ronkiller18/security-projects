// ============================================================
// findings.js — In-memory findings store
// ============================================================

let findingsStore = [];

// ---- Clear ----
export function clearFindings() {
    findingsStore = [];
}

// ---- Add ----
// source is set here so it always overwrites the factory default,
// giving each tool full control over the source label.
export function addFindings(source, findings) {
    if (!Array.isArray(findings)) return;

    const normalized = findings.map(finding => ({
        ...finding,
        source  // intentionally overwrites factory default
    }));

    findingsStore.push(...normalized);
}

// ---- Read ----
export function getFindings() {
    return [...findingsStore]; // return a copy — callers cannot mutate the store
}

export function getFindingCount() {
    return findingsStore.length;
}

export function hasFindings() {
    return findingsStore.length > 0;
}