// ============================================================
// cspAnalyzer.js — Content Security Policy analysis
// ============================================================

import { createFinding } from "../utils/createFinding.js";


export function analyzeCSP(policy) {
    const findings  = [];
    const normalized = policy.toLowerCase().trim();

    // Basic sanity check — must look like a CSP header
    const looksLikeCSP = /(default-src|script-src|style-src|img-src|object-src|frame-ancestors|connect-src)/i;
    if (!looksLikeCSP.test(normalized)) return [];

    // ---- unsafe-inline ----
    if (normalized.includes("'unsafe-inline'")) {
        findings.push(createFinding({
            type:           "Unsafe Inline Scripts",
            severity:       "High",
            confidence:     90,
            description:    "CSP allows inline JavaScript execution which weakens XSS protections.",
            recommendation: "Avoid unsafe-inline and use nonce- or hash-based policies."
        }));
    }

    // ---- unsafe-eval ----
    if (normalized.includes("'unsafe-eval'")) {
        findings.push(createFinding({
            type:           "Unsafe Eval Usage",
            severity:       "High",
            confidence:     90,
            description:    "unsafe-eval allows dangerous dynamic code execution.",
            recommendation: "Remove unsafe-eval from script-src directives."
        }));
    }

    // ---- Wildcard script-src ----
    // Regex instead of string includes — catches "script-src 'unsafe-inline' *" and spacing variants
    if (/script-src\s[^;]*\*/i.test(normalized)) {
        findings.push(createFinding({
            type:           "Wildcard Script Source",
            severity:       "High",
            confidence:     85,
            description:    "Wildcard script sources allow JavaScript from any domain.",
            recommendation: "Restrict script-src to trusted domains only."
        }));
    }

    // ---- Wildcard object-src ----
    if (/object-src\s[^;]*\*/i.test(normalized)) {
        findings.push(createFinding({
            type:           "Permissive object-src",
            severity:       "Medium",
            confidence:     80,
            description:    "object-src wildcard may allow unsafe embedded content.",
            recommendation: "Restrict or disable object-src entirely."
        }));
    }

    // ---- Missing frame-ancestors ----
    if (!normalized.includes("frame-ancestors")) {
        findings.push(createFinding({
            type:           "Missing frame-ancestors",
            severity:       "Medium",
            confidence:     75,
            description:    "Missing frame-ancestors directive may increase clickjacking risk.",
            recommendation: "Add frame-ancestors 'none' or a specific allow-list."
        }));
    }

    return findings;
}