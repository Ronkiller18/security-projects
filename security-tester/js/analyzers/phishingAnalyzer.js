// ============================================================
// phishingAnalyzer.js — URL Reputation + Phishing Detection
// Returns: Finding[] (empty array = no match)
// Each check is independent — one URL can trigger multiple findings
// ============================================================

import { createFinding } from "../utils/createFinding.js";


// ============================================================
// Constants
// ============================================================

// Anchored to start — avoids matching code like element.innerHTML
const LOOKS_LIKE_URL = /^https?:\/\/|^www\./i;

// Raw IP as domain e.g. http://192.168.1.1/login
const IP_AS_DOMAIN = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;

// Suspicious free / abuse-prone TLDs
const SUSPICIOUS_TLDS = /\.(xyz|tk|ml|ga|cf|gq|pw|top|click|loan|work|party|racing|download|stream)/i;

// Banking / brand trust-bait keywords
const BRAND_KEYWORDS = [
    /paypal/i, /apple/i, /google/i, /microsoft/i, /amazon/i,
    /netflix/i, /facebook/i, /instagram/i, /whatsapp/i, /bank/i
];

// Generic phishing action keywords
const ACTION_KEYWORDS = [
    /login/i, /verify/i, /secure/i, /account/i,
    /update/i, /confirm/i, /suspend/i, /unlock/i, /recover/i
];

// URL-encoded characters in the domain part (before first /)
const URL_ENCODED_DOMAIN = /%[0-9a-f]{2}/i;

// Homograph / lookalike characters commonly used in IDN attacks
const HOMOGRAPH_CHARS = /[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]/i;


// ============================================================
// Helpers
// ============================================================

// Extract just the hostname from a URL string (best-effort, no URL API needed)
function extractHostname(url) {
    // Strip protocol
    let host = url.replace(/^https?:\/\//i, "").replace(/^www\./i, "");
    // Strip path
    host = host.split("/")[0];
    // Strip port
    host = host.split(":")[0];
    return host.toLowerCase();
}

function countSubdomains(hostname) {
    // e.g. "a.b.paypal.com" → 4 parts → 2 subdomains above the registrable domain
    const parts = hostname.split(".");
    // registrable domain = last 2 parts (e.g. "paypal.com")
    return Math.max(0, parts.length - 2);
}


// ============================================================
// Main Export
// ============================================================

export function detectPhishing(input) {
    const trimmed = input.trim();

    if (!LOOKS_LIKE_URL.test(trimmed)) return [];

    const findings = [];
    const hostname  = extractHostname(trimmed);


    // ----------------------------------------------------------
    // Check 1: Raw IP address as domain
    // ----------------------------------------------------------
    if (IP_AS_DOMAIN.test(trimmed)) {
        findings.push(createFinding({
            type:           "IP Address Used as Domain",
            severity:       "High",
            confidence:     90,
            description:    "URL uses a raw IP address instead of a domain name. Legitimate services almost never do this — it is a strong indicator of phishing or malware hosting.",
            recommendation: "Do not visit or trust URLs using raw IP addresses as the host.",
            payloads:       ["http://192.168.1.1/login", "http://185.220.101.45/verify"]
        }));
    }


    // ----------------------------------------------------------
    // Check 2: Excessive subdomain depth
    // ----------------------------------------------------------
    const subdomainCount = countSubdomains(hostname);
    if (subdomainCount >= 3) {
        findings.push(createFinding({
            type:           "Excessive Subdomain Depth",
            severity:       "Medium",
            confidence:     75,
            description:    `Domain has ${subdomainCount} subdomain levels (e.g. paypal.com.verify.account.xyz). Attackers use deep subdomains to make the URL look legitimate at a glance.`,
            recommendation: "Check the actual registrable domain (last two parts before the TLD) — that is the real owner of the URL.",
            payloads:       ["http://secure.paypal.com.verify.login.xyz/"]
        }));
    }


    // ----------------------------------------------------------
    // Check 3: Brand keyword + suspicious TLD combination
    // ----------------------------------------------------------
    const hasBrandKeyword = BRAND_KEYWORDS.some(p => p.test(hostname));
    const hasSuspiciousTLD = SUSPICIOUS_TLDS.test(hostname);

    if (hasBrandKeyword && hasSuspiciousTLD) {
        findings.push(createFinding({
            type:           "Brand Impersonation",
            severity:       "High",
            confidence:     88,
            description:    "URL combines a well-known brand name with a suspicious or free TLD. This is a common phishing technique to appear legitimate while using a cheap throwaway domain.",
            recommendation: "Verify you are on the official domain. Official sites for major brands never use .xyz, .tk, .ml or similar TLDs.",
            payloads:       ["http://paypal-secure.tk", "http://apple-verify.xyz"]
        }));
    }


    // ----------------------------------------------------------
    // Check 4: Action keywords + suspicious TLD (original logic, enhanced)
    // ----------------------------------------------------------
    if (!hasBrandKeyword) {
        let actionScore = 0;
        ACTION_KEYWORDS.forEach(p => { if (p.test(hostname)) actionScore++; });
        if (hasSuspiciousTLD) actionScore++;

        if (actionScore >= 2) {
            findings.push(createFinding({
                type:           "Suspicious URL Pattern",
                severity:       "Medium",
                confidence:     70,
                description:    "URL contains multiple phishing-related keywords or suspicious domain patterns commonly associated with credential harvesting pages.",
                recommendation: "Verify domain ownership before entering any credentials or personal information.",
                payloads:       ["https://secure-login-update.xyz", "https://verify-account-now.tk"]
            }));
        }
    }


    // ----------------------------------------------------------
    // Check 5: URL-encoded characters in hostname
    // ----------------------------------------------------------
    if (URL_ENCODED_DOMAIN.test(hostname)) {
        findings.push(createFinding({
            type:           "URL-Encoded Domain Characters",
            severity:       "Medium",
            confidence:     80,
            description:    "The domain portion of this URL contains percent-encoded characters. This is used to obscure the real destination or bypass naive URL filters.",
            recommendation: "Decode the URL fully before visiting. Legitimate domains do not use percent-encoding in the hostname.",
            payloads:       ["http://pay%70al.com/login"]
        }));
    }


    // ----------------------------------------------------------
    // Check 6: Homograph / IDN lookalike characters
    // ----------------------------------------------------------
    if (HOMOGRAPH_CHARS.test(hostname)) {
        findings.push(createFinding({
            type:           "Homograph Domain Attack",
            severity:       "High",
            confidence:     85,
            description:    "Domain contains non-ASCII characters that visually resemble standard letters (e.g. 'а' looks like 'a' but is Cyrillic). This is used to impersonate trusted domains.",
            recommendation: "Check the URL encoding directly. Trusted services use ASCII-only domains.",
            payloads:       ["http://pаypal.com (Cyrillic 'а')"]
        }));
    }


    return findings;
}