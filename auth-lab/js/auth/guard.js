import {
    hasLoginSession,
    getSessionMode,
    removeLoginSession
} from "./storage.js";

// ==========================
// SESSION EXPIRY CHECK
// ==========================
function isSessionExpired() {

    const expiry =
        localStorage.getItem(
            "sessionExpiry"
        );

    if (!expiry) {
        return true;
    }

    return Date.now() >
        Number(expiry);
}

export function protectDashboardRoute() {

    const currentMode =
        getSessionMode();

    // ==========================
    // VULNERABLE MODE
    // ==========================
    if (currentMode === "vulnerable") {

        console.log(
            "[VULNERABLE MODE] Route protection disabled."
        );

        return;
    }

    // ==========================
    // SECURE MODE
    // ==========================
    if (currentMode === "secure") {

        const authenticated = hasLoginSession();

        const expired = isSessionExpired();

        // User NOT authenticated
        if (
            !authenticated ||
            expired
        ) {

            // Clear invalid session
            removeLoginSession();

            localStorage.removeItem(
                "sessionExpiry"
            );

            localStorage.removeItem(
                "userRole"
            );

            localStorage.removeItem(
                "sessionId"
            );

            window.location.href =
                "index.html?error=unauthorized";
        }
    }
}