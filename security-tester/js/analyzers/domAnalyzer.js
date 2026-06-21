// ============================================================
// domAnalyzer.js — DOM sink detection
// Returns: Finding[] (empty array = no match)
// ============================================================

import { createFinding } from "../utils/createFinding.js";

const DOM_PATTERNS = [
    /innerHTML\s*=/i,
    /outerHTML\s*=/i,
    /document\.write\s*\(/i,
    /insertAdjacentHTML\s*\(/i,
    /eval\s*\(/i,
    /location\.href\s*=/i,      // open redirect sink
    /location\.assign\s*\(/i,
    /location\.replace\s*\(/i
];

export function detectDOMRisk(input) {
    const matched = DOM_PATTERNS.some(pattern => pattern.test(input));
    if (!matched) return [];    // always return array

    return [
        createFinding({
            type:           "Unsafe DOM Manipulation",
            severity:       "High",
            confidence:     90,
            description:    "Potentially dangerous DOM sink detected.",
            recommendation: "Use textContent or safe templating instead of unsafe HTML injection methods.",
            payloads: [
                "element.innerHTML = userInput",
                "document.write(userData)",
                "eval(userInput)",
                "location.href = userInput"
            ]
        })
    ];
}