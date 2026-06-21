// ============================================================
// xssAnalyzer.js — XSS pattern detection
// Returns: Finding[] (empty array = no match)
// ============================================================

import { createFinding } from "../utils/createFinding.js";

const XSS_PATTERNS = [
    /<script[\s\S]*?>[\s\S]*?<\/script>/i,
    /<[^>]+on\w+\s*=/i,
    /onerror\s*=/i,
    /onload\s*=/i,
    /javascript\s*:/i,
    /<iframe[^>]+src\s*=/i      // iframe injection
];

export function detectXSS(input) {
    const matched = XSS_PATTERNS.some(pattern => pattern.test(input));
    if (!matched) return [];    // always return array

    return [
        createFinding({
            type:           "Cross-Site Scripting (XSS)",
            severity:       "High",
            confidence:     85,
            description:    "Potential client-side script injection pattern detected.",
            recommendation: "Avoid unsafe HTML rendering and sanitize untrusted input before inserting it into the DOM.",
            payloads: [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>"
            ]
        })
    ];
}