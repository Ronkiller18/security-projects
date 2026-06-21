// ============================================================
// jwtAnalyzer.js — JWT decode and security checks
// ============================================================

import { createFinding } from "../utils/createFinding.js";


function base64UrlDecode(str) {
    try {
        str = str.replace(/-/g, "+").replace(/_/g, "/");
        while (str.length % 4) str += "=";
        return atob(str);
    } catch {
        throw new Error("Base64 decode failed — malformed token segment.");
    }
}


export function analyzeJWT(token) {
    try {
        const parts = token.split(".");

        if (parts.length !== 3) {
            return { error: "Invalid JWT structure — expected 3 dot-separated segments." };
        }

        const header  = JSON.parse(base64UrlDecode(parts[0]));
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        const findings = [];

        // ---- alg: none (case-insensitive) ----
        if (header.alg?.toLowerCase() === "none") {
            findings.push(createFinding({
                type:           "Unsigned JWT",
                severity:       "High",
                confidence:     95,
                description:    "JWT uses alg:none which disables signature verification entirely.",
                recommendation: "Always enforce signed JWTs using RS256 or HS256."
            }));
        }

        // ---- Missing expiration ----
        if (!payload.exp) {
            findings.push(createFinding({
                type:           "Missing Expiration",
                severity:       "Medium",
                confidence:     85,
                description:    "JWT does not contain an expiration timestamp.",
                recommendation: "Add exp claims to reduce replay and token abuse risks."
            }));
        }

        // ---- Sensitive data in payload keys (note: checks key names only) ----
        const payloadKeys = Object.keys(payload).join(" ").toLowerCase();
        const sensitivePattern = /(password|passwd|secret|apikey|api_key|tokensecret)/i;

        if (sensitivePattern.test(payloadKeys)) {
            findings.push(createFinding({
                type:           "Sensitive Data Exposure",
                severity:       "High",
                confidence:     90,
                description:    "Sensitive information detected inside JWT payload.",
                recommendation: "Avoid storing passwords, API keys, or secrets inside JWTs."
            }));
        }

        return { header, payload, findings };

    } catch (e) {
        return { error: `Failed to decode JWT: ${e.message}` };
    }
}