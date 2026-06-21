// ============================================================
// headerAnalyzer.js — HTTP Security Header Analysis
// Returns: Finding[] (empty array = no issues found)
//
// Expects raw HTTP response headers as a string, e.g.:
//   Content-Security-Policy: default-src 'self'
//   X-Frame-Options: DENY
//   Strict-Transport-Security: max-age=31536000
// ============================================================

import { createFinding } from "../utils/createFinding.js";


// ============================================================
// Parser — turns raw header string into a key→value map
// ============================================================

function parseHeaders(raw) {
    const map = {};

    raw.split("\n").forEach(line => {
        const colonIndex = line.indexOf(":");
        if (colonIndex === -1) return;

        const name  = line.slice(0, colonIndex).trim().toLowerCase();
        const value = line.slice(colonIndex + 1).trim().toLowerCase();

        if (name) map[name] = value;
    });

    return map;
}


// ============================================================
// Main Export
// ============================================================

export function analyzeHeaders(raw) {
    const findings = [];
    const headers  = parseHeaders(raw);

    // Bail early if no recognisable headers found
    const knownHeaders = [
        "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options",
        "referrer-policy", "permissions-policy",
        "x-xss-protection", "cache-control"
    ];

    const hasAny = knownHeaders.some(h => h in headers);
    if (!hasAny) return [];


    // ----------------------------------------------------------
    // 1. Content-Security-Policy
    // ----------------------------------------------------------
    if (!("content-security-policy" in headers)) {
        findings.push(createFinding({
            type:           "Missing Content-Security-Policy",
            severity:       "High",
            confidence:     95,
            description:    "No Content-Security-Policy header detected. Without CSP, the browser has no restrictions on which scripts, styles, or resources can be loaded — making XSS attacks significantly more impactful.",
            recommendation: "Add a Content-Security-Policy header with at minimum: default-src 'self'; script-src 'self'."
        }));
    }


    // ----------------------------------------------------------
    // 2. Strict-Transport-Security (HSTS)
    // ----------------------------------------------------------
    if (!("strict-transport-security" in headers)) {
        findings.push(createFinding({
            type:           "Missing Strict-Transport-Security (HSTS)",
            severity:       "High",
            confidence:     90,
            description:    "No HSTS header found. Without HSTS, browsers may accept HTTP connections even when HTTPS is available, leaving users vulnerable to downgrade and man-in-the-middle attacks.",
            recommendation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        }));
    } else {
        const hsts = headers["strict-transport-security"];

        // Check max-age is sufficient (at least 6 months = 15552000 seconds)
        const maxAgeMatch = hsts.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
            const maxAge = parseInt(maxAgeMatch[1], 10);
            if (maxAge < 15552000) {
                findings.push(createFinding({
                    type:           "Weak HSTS max-age",
                    severity:       "Medium",
                    confidence:     85,
                    description:    `HSTS max-age is set to ${maxAge} seconds (less than 6 months). Short durations reduce protection because browsers may fall back to HTTP before the policy is re-validated.`,
                    recommendation: "Set max-age to at least 31536000 (1 year) and add includeSubDomains."
                }));
            }
        }

        if (!hsts.includes("includesubdomains")) {
            findings.push(createFinding({
                type:           "HSTS Missing includeSubDomains",
                severity:       "Low",
                confidence:     75,
                description:    "HSTS does not include the includeSubDomains directive. Subdomains may still be accessible over plain HTTP.",
                recommendation: "Add includeSubDomains to your HSTS header."
            }));
        }
    }


    // ----------------------------------------------------------
    // 3. X-Frame-Options
    // ----------------------------------------------------------
    if (!("x-frame-options" in headers)) {
        findings.push(createFinding({
            type:           "Missing X-Frame-Options",
            severity:       "Medium",
            confidence:     85,
            description:    "No X-Frame-Options header found. Without this, the page can be embedded in an iframe on any domain, enabling clickjacking attacks.",
            recommendation: "Add: X-Frame-Options: DENY — or use frame-ancestors in your CSP."
        }));
    } else {
        const xfo = headers["x-frame-options"];
        if (!["deny", "sameorigin"].includes(xfo.trim())) {
            findings.push(createFinding({
                type:           "Weak X-Frame-Options Value",
                severity:       "Medium",
                confidence:     80,
                description:    `X-Frame-Options is set to "${xfo}" which is not a recognised safe value. Only DENY and SAMEORIGIN are valid.`,
                recommendation: "Set X-Frame-Options to DENY unless you specifically need same-origin framing."
            }));
        }
    }


    // ----------------------------------------------------------
    // 4. X-Content-Type-Options
    // ----------------------------------------------------------
    if (!("x-content-type-options" in headers)) {
        findings.push(createFinding({
            type:           "Missing X-Content-Type-Options",
            severity:       "Medium",
            confidence:     85,
            description:    "No X-Content-Type-Options header found. Without nosniff, browsers may MIME-sniff responses and execute files as a different content type than declared — enabling content injection attacks.",
            recommendation: "Add: X-Content-Type-Options: nosniff"
        }));
    } else if (headers["x-content-type-options"].trim() !== "nosniff") {
        findings.push(createFinding({
            type:           "Incorrect X-Content-Type-Options Value",
            severity:       "Medium",
            confidence:     85,
            description:    "X-Content-Type-Options is present but not set to 'nosniff'. Only the value 'nosniff' is recognised by browsers.",
            recommendation: "Set X-Content-Type-Options: nosniff exactly."
        }));
    }


    // ----------------------------------------------------------
    // 5. Referrer-Policy
    // ----------------------------------------------------------
    const STRONG_REFERRER_POLICIES = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin"
    ];

    if (!("referrer-policy" in headers)) {
        findings.push(createFinding({
            type:           "Missing Referrer-Policy",
            severity:       "Low",
            confidence:     70,
            description:    "No Referrer-Policy header found. Browsers default to sending the full URL as a referrer, which may leak sensitive path or query string data to third parties.",
            recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin"
        }));
    } else {
        const rp = headers["referrer-policy"].trim();
        if (!STRONG_REFERRER_POLICIES.includes(rp)) {
            findings.push(createFinding({
                type:           "Weak Referrer-Policy",
                severity:       "Low",
                confidence:     70,
                description:    `Referrer-Policy is set to "${rp}" which may leak URL data to external sites. Policies like "unsafe-url" or "origin-when-cross-origin" send more data than necessary.`,
                recommendation: "Use strict-origin-when-cross-origin or no-referrer for stronger privacy."
            }));
        }
    }


    // ----------------------------------------------------------
    // 6. Permissions-Policy
    // ----------------------------------------------------------
    if (!("permissions-policy" in headers)) {
        findings.push(createFinding({
            type:           "Missing Permissions-Policy",
            severity:       "Low",
            confidence:     65,
            description:    "No Permissions-Policy header found. Without it, the browser grants default access to sensitive APIs such as camera, microphone, and geolocation.",
            recommendation: "Add a Permissions-Policy header to restrict access to browser features not required by your application."
        }));
    }


    // ----------------------------------------------------------
    // 7. X-XSS-Protection (legacy — flag if enabling unsafe mode)
    // ----------------------------------------------------------
    if ("x-xss-protection" in headers) {
        const xxss = headers["x-xss-protection"].trim();
        // "1; mode=block" is acceptable but deprecated
        // "1" without mode=block can actually introduce vulnerabilities
        if (xxss === "1" || xxss === "0") {
            findings.push(createFinding({
                type:           "Weak X-XSS-Protection Configuration",
                severity:       "Low",
                confidence:     60,
                description:    "X-XSS-Protection is set without mode=block, or is disabled. This header is deprecated in modern browsers and should not be relied on for XSS protection.",
                recommendation: "Remove X-XSS-Protection entirely and rely on a strong Content-Security-Policy instead."
            }));
        }
    }


    // ----------------------------------------------------------
    // 8. Cache-Control for sensitive pages
    // ----------------------------------------------------------
    if ("cache-control" in headers) {
        const cc = headers["cache-control"];
        if (!cc.includes("no-store") && !cc.includes("no-cache")) {
            findings.push(createFinding({
                type:           "Potentially Cacheable Sensitive Response",
                severity:       "Low",
                confidence:     60,
                description:    "Cache-Control does not include no-store or no-cache. If this is an authenticated or sensitive page, responses may be cached by proxies or the browser and exposed to other users.",
                recommendation: "For authenticated pages add: Cache-Control: no-store, no-cache, must-revalidate"
            }));
        }
    }


    return findings;
}