// ============================================================
// storageAnalyzer.js — localStorage / sessionStorage analysis
// Returns: Finding[] (empty array = no issues found)
//
// storageType: "localStorage" | "sessionStorage"
// Used by storageTool.js for both tabs — same logic, different label.
//
// Expects pasted JavaScript code, e.g.:
//   localStorage.setItem('token', jwtValue)
//   sessionStorage.setItem('user', JSON.stringify(userData))
// ============================================================

import { createFinding } from "../utils/createFinding.js";


// ============================================================
// Constants
// ============================================================

// Key names that strongly suggest sensitive data
const SENSITIVE_KEY_PATTERNS = [
    /token/i,   /auth/i,    /jwt/i,     /session/i,
    /password/i,/passwd/i,  /secret/i,  /apikey/i,
    /api_key/i, /credential/i, /private/i, /access/i,
    /refresh/i, /bearer/i,  /identity/i
];

// Patterns that look like JWT values (three base64 segments)
const JWT_VALUE_PATTERN = /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/;

// Bearer token pattern
const BEARER_PATTERN = /bearer\s+[a-zA-Z0-9\-._~+/]+=*/i;

// setItem calls — capture key argument
const SET_ITEM_PATTERN = /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`]([^'"`]+)['"`]/gi;

// getItem calls — capture key argument
const GET_ITEM_PATTERN = /(?:localStorage|sessionStorage)\.getItem\s*\(\s*['"`]([^'"`]+)['"`]/gi;

// JSON.stringify inside setItem
const STRINGIFY_IN_SETITEM = /\.setItem\s*\([^,]+,\s*JSON\.stringify\s*\(/gi;

// Any localStorage/sessionStorage usage at all
const ANY_STORAGE_USAGE = /(?:localStorage|sessionStorage)\s*\.\s*(?:setItem|getItem|removeItem|clear|key)/gi;

// eval or Function constructor with storage value
const EVAL_WITH_STORAGE = /eval\s*\(.*(?:localStorage|sessionStorage)|(?:localStorage|sessionStorage).*eval\s*\(/gi;


// ============================================================
// Helpers
// ============================================================

function extractSetItemKeys(code) {
    const keys = [];
    let match;
    const re = new RegExp(SET_ITEM_PATTERN.source, "gi");
    while ((match = re.exec(code)) !== null) {
        keys.push(match[1]);
    }
    return keys;
}

function extractGetItemKeys(code) {
    const keys = [];
    let match;
    const re = new RegExp(GET_ITEM_PATTERN.source, "gi");
    while ((match = re.exec(code)) !== null) {
        keys.push(match[1]);
    }
    return keys;
}

function isSensitiveKey(key) {
    return SENSITIVE_KEY_PATTERNS.some(p => p.test(key));
}


// ============================================================
// Main Export
// storageType: "localStorage" | "sessionStorage"
// ============================================================

export function analyzeStorage(code, storageType) {
    const findings  = [];
    const label     = storageType; // used in finding descriptions

    // Bail early if no storage usage detected at all
    if (!ANY_STORAGE_USAGE.test(code)) return [];

    const setKeys = extractSetItemKeys(code);
    const getKeys = extractGetItemKeys(code);
    const allKeys = [...new Set([...setKeys, ...getKeys])];


    // ----------------------------------------------------------
    // Check 1: Sensitive key names in setItem calls
    // ----------------------------------------------------------
    const sensitiveSetKeys = setKeys.filter(isSensitiveKey);

    if (sensitiveSetKeys.length > 0) {
        findings.push(createFinding({
            type:           `Sensitive Data Stored in ${label}`,
            severity:       "High",
            confidence:     88,
            description:    `Potentially sensitive data is being written to ${label} using keys: ${sensitiveSetKeys.map(k => `"${k}"`).join(", ")}. ${label} is accessible to any JavaScript on the page — an XSS attack can read and exfiltrate this data instantly.`,
            recommendation: `Never store tokens, credentials, or session identifiers in ${label}. Use HttpOnly cookies instead, which are inaccessible to JavaScript.`,
            payloads:       sensitiveSetKeys.map(k => `${label}.setItem('${k}', ...)`)
        }));
    }


    // ----------------------------------------------------------
    // Check 2: JWT value pattern detected in the code
    // ----------------------------------------------------------
    if (JWT_VALUE_PATTERN.test(code)) {
        findings.push(createFinding({
            type:           `JWT Token Written to ${label}`,
            severity:       "High",
            confidence:     92,
            description:    `A JWT token value was detected in code that writes to ${label}. JWTs stored in ${label} can be stolen via XSS, used to impersonate users, and cannot be revoked server-side once stolen.`,
            recommendation: `Store JWTs in HttpOnly cookies. If ${label} must be used, ensure a strict CSP with no unsafe-inline to reduce XSS risk.`,
            payloads:       ["localStorage.setItem('token', 'eyJhbGc...')"]
        }));
    }


    // ----------------------------------------------------------
    // Check 3: Bearer token pattern
    // ----------------------------------------------------------
    if (BEARER_PATTERN.test(code)) {
        findings.push(createFinding({
            type:           `Bearer Token in ${label}`,
            severity:       "High",
            confidence:     88,
            description:    `A Bearer token pattern was detected in code using ${label}. Bearer tokens grant API access and are high-value targets for XSS-based theft.`,
            recommendation: `Do not store Bearer tokens in ${label}. Use session management via HttpOnly cookies on a secure backend.`,
            payloads:       [`${label}.setItem('auth', 'Bearer eyJ...')`]
        }));
    }


    // ----------------------------------------------------------
    // Check 4: JSON.stringify inside setItem — serialised objects
    // ----------------------------------------------------------
    if (STRINGIFY_IN_SETITEM.test(code)) {
        // Check if any setItem key storing serialised data is sensitive
        const hasSensitiveSerialised = setKeys.some(isSensitiveKey);

        findings.push(createFinding({
            type:           `Serialised Object Stored in ${label}`,
            severity:       hasSensitiveSerialised ? "High" : "Medium",
            confidence:     hasSensitiveSerialised ? 85 : 70,
            description:    `Code serialises an object with JSON.stringify() before writing it to ${label}. Serialised objects may contain sensitive fields even if the key name looks innocuous. All content is readable via XSS.`,
            recommendation: `Audit what properties are inside serialised objects before storing them. Remove any sensitive fields and avoid storing authentication state client-side.`,
            payloads:       [`${label}.setItem('user', JSON.stringify(userData))`]
        }));
    }


    // ----------------------------------------------------------
    // Check 5: Sensitive keys in getItem — reading sensitive data
    // ----------------------------------------------------------
    const sensitiveGetKeys = getKeys.filter(isSensitiveKey);

    if (sensitiveGetKeys.length > 0) {
        findings.push(createFinding({
            type:           `Sensitive ${label} Keys Read in Code`,
            severity:       "Medium",
            confidence:     75,
            description:    `Code reads sensitive keys from ${label}: ${sensitiveGetKeys.map(k => `"${k}"`).join(", ")}. If this data exists in storage, it confirms sensitive information is persisted client-side and accessible to XSS.`,
            recommendation: `If these keys hold sensitive data, move that data to server-managed HttpOnly cookies. Review whether client-side code really needs access to this data.`,
            payloads:       sensitiveGetKeys.map(k => `${label}.getItem('${k}')`)
        }));
    }


    // ----------------------------------------------------------
    // Check 6: eval() used with storage values — code injection risk
    // ----------------------------------------------------------
    if (EVAL_WITH_STORAGE.test(code)) {
        findings.push(createFinding({
            type:           `eval() Used With ${label} Data`,
            severity:       "High",
            confidence:     90,
            description:    `Code passes ${label} data into eval() or a similar dynamic code execution function. If an attacker can write to ${label} (e.g. via a related XSS), this creates a direct code injection vector.`,
            recommendation: `Never pass storage values to eval(), setTimeout(string), setInterval(string), or Function(). Use JSON.parse() for structured data only.`,
            payloads:       [`eval(${label}.getItem('code'))`]
        }));
    }


    // ----------------------------------------------------------
    // Check 7: General storage usage notice (always added as Low)
    // Only fires if no higher-severity findings were triggered,
    // to avoid noise when serious issues are already flagged
    // ----------------------------------------------------------
    if (findings.length === 0 && allKeys.length > 0) {
        findings.push(createFinding({
            type:           `${label} Usage Detected`,
            severity:       "Low",
            confidence:     60,
            description:    `Code uses ${label} to store data with key(s): ${allKeys.map(k => `"${k}"`).join(", ")}. While no obviously sensitive keys were detected, all ${label} data is accessible to JavaScript and vulnerable to XSS-based theft.`,
            recommendation: `Audit all data written to ${label}. Prefer server-side session management for anything security-relevant.`,
            payloads:       allKeys.map(k => `${label}.setItem('${k}', ...)`)
        }));
    }


    return findings;
}