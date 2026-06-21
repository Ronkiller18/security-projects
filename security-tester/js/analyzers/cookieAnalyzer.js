// ============================================================
// cookieAnalyzer.js — Cookie Security Analysis
// Returns: Finding[] (empty array = no issues found)
//
// Expects one or more Set-Cookie header lines, e.g.:
//   Set-Cookie: session=abc123; Path=/
//   Set-Cookie: token=xyz; HttpOnly; Secure; SameSite=Strict
// ============================================================

import { createFinding } from "../utils/createFinding.js";


// ============================================================
// Constants
// ============================================================

// Cookie names that suggest sensitive data
const SENSITIVE_NAME_PATTERNS = [
    /session/i, /token/i, /auth/i, /jwt/i,
    /user/i,    /admin/i, /id/i,  /key/i,
    /secret/i,  /pass/i,  /cred/i
];

// SameSite values considered strong
const STRONG_SAMESITE = ["strict", "lax"];


// ============================================================
// Parser — extracts cookie name + attributes from one line
// ============================================================

function parseCookieLine(line) {
    // Strip "Set-Cookie:" prefix if present
    const cleaned = line.replace(/^set-cookie:\s*/i, "").trim();
    if (!cleaned) return null;

    const parts = cleaned.split(";").map(p => p.trim());

    // First part is always name=value
    const nameValuePair = parts[0];
    const eqIndex       = nameValuePair.indexOf("=");
    const name          = eqIndex !== -1
        ? nameValuePair.slice(0, eqIndex).trim()
        : nameValuePair.trim();

    const attributeString = parts.slice(1).join(";").toLowerCase();

    return {
        name,
        raw:          cleaned,
        httpOnly:     /\bhttponly\b/i.test(attributeString),
        secure:       /\bsecure\b/i.test(attributeString),
        sameSite:     extractSameSite(attributeString),
        path:         extractAttribute(attributeString, "path"),
        domain:       extractAttribute(attributeString, "domain"),
        maxAge:       extractAttribute(attributeString, "max-age"),
        expires:      extractAttribute(attributeString, "expires"),
        isSensitive:  SENSITIVE_NAME_PATTERNS.some(p => p.test(name))
    };
}

function extractSameSite(attrs) {
    const match = attrs.match(/samesite=(\w+)/i);
    return match ? match[1].toLowerCase() : null;
}

function extractAttribute(attrs, name) {
    const match = attrs.match(new RegExp(`${name}=([^;]+)`, "i"));
    return match ? match[1].trim() : null;
}


// ============================================================
// Main Export
// ============================================================

export function analyzeCookies(raw) {
    const findings = [];

    // Split into individual lines and find Set-Cookie lines
    const lines = raw.split("\n").filter(line => {
        const lower = line.toLowerCase().trim();
        // Accept lines starting with "set-cookie:" or bare cookie strings with ";"
        return lower.startsWith("set-cookie:") || lower.includes(";") || lower.includes("=");
    });

    if (lines.length === 0) return [];

    const cookies = lines
        .map(parseCookieLine)
        .filter(Boolean);

    if (cookies.length === 0) return [];

    cookies.forEach(cookie => {
        const label    = cookie.name || "unnamed";
        // Bump confidence for sensitive cookie names
        const sensitiveBoost = cookie.isSensitive ? 10 : 0;


        // --------------------------------------------------------
        // Check 1: Missing HttpOnly
        // --------------------------------------------------------
        if (!cookie.httpOnly) {
            findings.push(createFinding({
                type:           `Missing HttpOnly — ${label}`,
                severity:       cookie.isSensitive ? "High" : "Medium",
                confidence:     (cookie.isSensitive ? 90 : 75) + sensitiveBoost,
                description:    `Cookie "${label}" is missing the HttpOnly flag. Without it, the cookie is accessible via JavaScript (document.cookie), making it vulnerable to theft through XSS attacks.`,
                recommendation: `Add HttpOnly to the Set-Cookie directive: Set-Cookie: ${label}=...; HttpOnly`
            }));
        }


        // --------------------------------------------------------
        // Check 2: Missing Secure flag
        // --------------------------------------------------------
        if (!cookie.secure) {
            findings.push(createFinding({
                type:           `Missing Secure Flag — ${label}`,
                severity:       cookie.isSensitive ? "High" : "Medium",
                confidence:     (cookie.isSensitive ? 90 : 75) + sensitiveBoost,
                description:    `Cookie "${label}" is missing the Secure flag. Without it, the cookie will be transmitted over unencrypted HTTP connections, exposing it to interception.`,
                recommendation: `Add Secure to the Set-Cookie directive: Set-Cookie: ${label}=...; Secure`
            }));
        }


        // --------------------------------------------------------
        // Check 3: Missing SameSite
        // --------------------------------------------------------
        if (!cookie.sameSite) {
            findings.push(createFinding({
                type:           `Missing SameSite — ${label}`,
                severity:       "Medium",
                confidence:     80,
                description:    `Cookie "${label}" has no SameSite attribute. Without it, the browser defaults to Lax in modern browsers, but older browsers may send the cookie with all cross-site requests, enabling CSRF attacks.`,
                recommendation: `Add SameSite=Strict for authentication cookies, or SameSite=Lax for general cookies.`
            }));
        } else if (!STRONG_SAMESITE.includes(cookie.sameSite)) {
            // SameSite=None without Secure is a serious issue
            if (cookie.sameSite === "none" && !cookie.secure) {
                findings.push(createFinding({
                    type:           `SameSite=None Without Secure — ${label}`,
                    severity:       "High",
                    confidence:     95,
                    description:    `Cookie "${label}" uses SameSite=None but is missing the Secure flag. Browsers reject SameSite=None cookies without Secure, and this combination exposes the cookie to cross-site request forgery.`,
                    recommendation: `Either add Secure flag alongside SameSite=None, or switch to SameSite=Strict.`
                }));
            } else if (cookie.sameSite === "none") {
                findings.push(createFinding({
                    type:           `SameSite=None — Broad Cross-Site Access — ${label}`,
                    severity:       "Medium",
                    confidence:     80,
                    description:    `Cookie "${label}" uses SameSite=None, allowing it to be sent with all cross-site requests. This should only be used for intentional cross-site scenarios like embedded widgets.`,
                    recommendation: `Use SameSite=Strict or SameSite=Lax unless cross-site sending is explicitly required.`
                }));
            }
        }


        // --------------------------------------------------------
        // Check 4: Sensitive cookie missing both HttpOnly + Secure
        // --------------------------------------------------------
        if (cookie.isSensitive && !cookie.httpOnly && !cookie.secure) {
            findings.push(createFinding({
                type:           `Sensitive Cookie Fully Exposed — ${label}`,
                severity:       "High",
                confidence:     95,
                description:    `Cookie "${label}" appears to store sensitive data (based on its name) but has neither HttpOnly nor Secure set. It can be read by JavaScript and transmitted over unencrypted connections.`,
                recommendation: `Always set both HttpOnly and Secure on authentication, session, and token cookies.`
            }));
        }


        // --------------------------------------------------------
        // Check 5: No expiry — session cookie leaking on shared devices
        // --------------------------------------------------------
        if (!cookie.maxAge && !cookie.expires) {
            findings.push(createFinding({
                type:           `No Expiry Set — ${label}`,
                severity:       "Low",
                confidence:     60,
                description:    `Cookie "${label}" has no Max-Age or Expires attribute, making it a session cookie that persists until the browser is closed. On shared or public devices this can lead to session persistence after a user walks away.`,
                recommendation: `Set an appropriate Max-Age or Expires for all cookies, especially authentication ones.`
            }));
        }
    });

    return findings;
}