// ============================================================
// sanitize.js — HTML escaping utility
// ============================================================

export function escapeHTML(str) {
    // Guard: handle null, undefined, numbers, booleans safely
    if (str == null) return "";
    const s = String(str);
    return s
        .replace(/&/g,  "&amp;")
        .replace(/</g,  "&lt;")
        .replace(/>/g,  "&gt;")
        .replace(/"/g,  "&quot;")
        .replace(/'/g,  "&#039;");
}