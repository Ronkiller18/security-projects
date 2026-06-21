import {
    setLoginSession,
    removeLoginSession,
    hasLoginSession,
    setSessionId,
    getSessionId,
    setSessionMode,
    getSessionMode
} from "./storage.js";

import {
    incrementFailedAttempts,
    resetFailedAttempts,
    isLockedOut,
    getRemainingLockTime
} from "./rate-limit.js";

import {
    showMessage,
    initializePasswordStrengthUI,
    renderSessionDisplay,
    renderRouteProtectionStatus,
    renderJwtDisplay,
    renderSessionTimeline,
    initializeLockoutCountdown,
    renderRoleDisplay,
    renderSessionMetadata
} from "./ui.js";

//import { validateLogin } from "./auth.js";

import { analyzePasswordStrength } from "./password-checker.js";
import { generateSessionId } from "./session.js";
import { protectDashboardRoute } from "./guard.js";
import { validateUserRole } from "./roles.js";

// ==========================
// DOM ELEMENTS
// ==========================
const messageBox = document.getElementById("message");
const exploitBtn = document.getElementById("autoExploitBtn");
const resetBtn = document.getElementById("resetExploitBtn");
const fixateSessionBtn = document.getElementById("fixateSessionBtn");
const loginForm = document.getElementById("loginForm");
const logoutBtn = document.getElementById("logoutBtn");

const sessionModeInputs = document.querySelectorAll('input[name="sessionMode"]');

// ==========================
// GET CURRENT SESSION MODE
// ==========================
function getCurrentSessionMode() {

    let selectedMode = "vulnerable";

    sessionModeInputs.forEach(input => {

        if (input.checked) {
            selectedMode = input.value;
        }
    });

    return selectedMode;
}

// ==========================
// LOGIN HANDLER
// ==========================
if (loginForm) {
    loginForm.addEventListener("submit", (event) => {
        event.preventDefault();

        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        // ==========================
        // CHECK LOCKOUT
        // ==========================
        if (isLockedOut()) {

            const remaining =
                getRemainingLockTime();

            showMessage(
                messageBox,
                `Too many failed attempts. Try again in ${remaining}s.`,
                "#f87171"
            );

            return;
        }

        const role = validateUserRole(username, password);

        const isValid = role !== null;

        if (isValid) {

            resetFailedAttempts();

            setLoginSession();

            // Session expires after 60 seconds
            localStorage.setItem(
                "sessionExpiry",
                Date.now() + 60000
            );

            localStorage.setItem("userRole", role);

            const currentMode = getCurrentSessionMode();

            setSessionMode(currentMode);    

            let sessionId = getSessionId();

            // ==========================
            // VULNERABLE MODE
            // ==========================
            if (currentMode === "vulnerable") {

                // Reuse attacker-controlled session
                if (!sessionId) {

                    sessionId = generateSessionId();

                    setSessionId(sessionId);
                }
            }

            // ==========================
            // SECURE MODE
            // ==========================
            if (currentMode === "secure") {

                // Regenerate session after login
                sessionId = generateSessionId();

                setSessionId(sessionId);
            }

            showMessage(
                messageBox,
                `Login successful | Session: ${sessionId}`,
                "lightgreen"
            );

            window.location.href = "dashboard.html";
        } else {

            incrementFailedAttempts();

            showMessage(
                messageBox,
                "Invalid credentials",
                "red"
            );
        }
    });
}

// ==========================
// SESSION CHECK
// ==========================
if (messageBox && hasLoginSession()) {
    showMessage(
        messageBox,
        "⚠️ Existing client-side session detected in localStorage.",
        "orange"
    );
}

// ==========================
// EXPLOIT BUTTON
// ==========================
if (exploitBtn) {
    exploitBtn.addEventListener("click", () => {

        localStorage.setItem(
            "userRole",
            "admin"
        );

        setLoginSession();

        showMessage(
            messageBox,
            "⚠️ Exploit successful: Client-side session and admin role injected.",
            "orange"
        );
    });
}

// ==========================
// RESET BUTTON
// ==========================
if (resetBtn) {
    resetBtn.addEventListener("click", () => {

        removeLoginSession();
        localStorage.removeItem("sessionId");
        localStorage.removeItem("userRole");

        showMessage(
            messageBox,
            "Session cleared. You are logged out.",
            "white"
        );
    });
}

// ==========================
// LOGOUT BUTTON
// ==========================
if (logoutBtn) {

    logoutBtn.addEventListener("click", () => {

        removeLoginSession();

        localStorage.removeItem("userRole");

        localStorage.removeItem("sessionId");

        localStorage.removeItem("sessionMode");

            showMessage(
                messageBox,
                "Logged out successfully.",
                "#4ade80"
            );

            window.location.href = "index.html";
        }
    );
}

// ==========================
// SESSION FIXATION EXPLOIT
// ==========================
if (fixateSessionBtn) {

    fixateSessionBtn.addEventListener("click", () => {

        const attackerSession =
            "attacker-session-123";

        setSessionId(attackerSession);

        showMessage(
            messageBox,
            `Session fixed to: ${attackerSession}`,
            "orange"
        );
    });
}

// ==========================
// INITIALIZE UI SYSTEMS
// ==========================
initializePasswordStrengthUI(
    analyzePasswordStrength
);

renderRouteProtectionStatus(
    getSessionMode
);

renderSessionDisplay(
    getSessionId,
    getSessionMode
);

renderRoleDisplay();

renderSessionMetadata(
    getSessionMode
);

renderJwtDisplay();

renderSessionTimeline(
    getSessionMode,
    getSessionId
);

initializeLockoutCountdown(
    isLockedOut,
    getRemainingLockTime
);

// ==========================
// ROUTE PROTECTION
// ==========================
if (
    window.location.pathname.includes(
        "dashboard.html"
    )
) {

    const currentMode =
        getSessionMode();

    // Secure mode only
    if (currentMode === "secure") {

        protectDashboardRoute();
    }
}

// ==========================
// AUTH ERROR MESSAGE
// ==========================
const params =
    new URLSearchParams(
        window.location.search
    );

const authError =
    params.get("error");

if (
    authError === "unauthorized"
) {

    showMessage(
        messageBox,
        "⚠️ Access denied. Please login first.",
        "#f87171"
    );
}