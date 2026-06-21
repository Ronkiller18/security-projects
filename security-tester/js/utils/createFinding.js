// ============================================================
// createFinding.js — Finding factory
// Centralises the finding shape so every analyzer
// produces a consistent object.
// ============================================================

const VALID_SEVERITIES = ["High", "Medium", "Low"];

export function createFinding({
    type,
    severity,
    description,
    recommendation,
    confidence = 100,
    payloads   = [],
    source     = ""     // can be overwritten by addFindings()
}) {
    // Validate severity — prevents bad data reaching scoring/badges
    if (!VALID_SEVERITIES.includes(severity)) {
        console.warn(`createFinding: invalid severity "${severity}" on "${type}" — defaulting to "Low"`);
        severity = "Low";
    }

    return {
        type,
        severity,
        description,
        recommendation,
        confidence,
        payloads,
        source
    };
}