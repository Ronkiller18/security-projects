// ===========================================================
// Open Redirect Demo
// ===========================================================

const ALLOWED_DOMAINS = [
    "google.com",
    "github.com"
];

// ===========================================================
// Elements
// ===========================================================

const redirectElements = {

    vulnerableInput:
        document.getElementById("redirectInputVuln"),

    safeInput:
        document.getElementById("redirectInputSafe")
};

// ===========================================================
// Vulnerable Redirect
// ===========================================================

function redirectUser() {

    const url =
        redirectElements.vulnerableInput?.value.trim();

    if (!url) {
        alert("⚠️ Please enter a URL");
        return;
    }

    // 🚨 Vulnerable
    window.location.href = url;
}

// ===========================================================
// Safe Redirect
// ===========================================================

function safeRedirect() {

    const input =
        redirectElements.safeInput?.value.trim();

    if (!input) {
        alert("⚠️ Please enter a URL");
        return;
    }

    try {

        const url = new URL(input);

        const isAllowed =
            ALLOWED_DOMAINS.some(domain =>
                url.hostname.includes(domain)
            );

        if (isAllowed) {

            window.location.href = url.href;

        } else {

            alert("⚠️ Blocked: Untrusted domain");
        }

    } catch {

        alert("❌ Invalid URL");
    }
}