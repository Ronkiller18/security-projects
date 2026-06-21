// ==========================
// GENERIC MESSAGE RENDERER
// ==========================
export function showMessage(
    element,
    text,
    color
) {
    if (!element) return;

    element.textContent = text;
    element.style.color = color;
}

// ==========================
// PASSWORD STRENGTH UI
// ==========================
export function initializePasswordStrengthUI(
    analyzePasswordStrength
) {

    const passwordInput =
        document.getElementById("password");

    const passwordStrength =
        document.getElementById(
            "passwordStrength"
        );

    const passwordFeedback =
        document.getElementById(
            "passwordFeedback"
        );

    if (
        !passwordInput ||
        !passwordStrength ||
        !passwordFeedback
    ) {
        return;
    }

    passwordInput.addEventListener(
        "input",
        () => {

            const result =
                analyzePasswordStrength(
                    passwordInput.value
                );

            // Strength label
            passwordStrength.textContent =
                `Strength: ${result.strength}`;

            passwordStrength.className =
                `password-strength ${result.className}`;

            // Feedback list
            passwordFeedback.innerHTML = "";

            result.feedback.forEach(item => {

                const li =
                    document.createElement("li");

                li.textContent = item;

                passwordFeedback.appendChild(li);
            });
        }
    );
}

// ==========================
// SESSION DISPLAY UI
// ==========================
export function renderSessionDisplay(
    getSessionId,
    getSessionMode
) {

    const sessionDisplay =
        document.getElementById(
            "sessionDisplay"
        );

    const sessionRiskBadge =
        document.getElementById(
            "sessionRiskBadge"
        );

    const sessionWarning =
        document.getElementById(
            "sessionWarning"
        );

    if (
        !sessionDisplay ||
        !sessionRiskBadge ||
        !sessionWarning
    ) {
        return;
    }

    const activeSession =
        getSessionId();

    const currentMode =
        getSessionMode();

    sessionDisplay.textContent =
        activeSession || "No active session";

    sessionRiskBadge.classList.remove(
        "high",
        "low"
    );
    // ==========================
    // VULNERABLE MODE
    // ==========================
    if (currentMode === "vulnerable") {

        sessionRiskBadge.textContent =
            "HIGH RISK";

        sessionRiskBadge.classList.add(
            "high"
        );

        sessionWarning.textContent =
            "Session ID was NOT regenerated after login. " +
            "An attacker who knows this value may hijack the session.";
    }

    // ==========================
    // SECURE MODE
    // ==========================
    if (currentMode === "secure") {

        sessionRiskBadge.textContent =
            "LOW RISK";

        sessionRiskBadge.classList.add(
            "low"
        );

        sessionWarning.textContent =
            "Session ID was regenerated after login. " +
            "Previously fixed attacker sessions become invalid.";
    }
}

// ==========================
// ROUTE PROTECTION UI
// ==========================
export function renderRouteProtectionStatus(
    getSessionMode
) {

    const routeBadge =
        document.getElementById(
            "routeProtectionBadge"
        );

    const routeMessage =
        document.getElementById(
            "routeProtectionMessage"
        );

    if (
        !routeBadge ||
        !routeMessage
    ) {
        return;
    }

    const currentMode = getSessionMode();

    routeBadge.classList.remove(
        "high",
        "low"
    );    

    // ==========================
    // VULNERABLE MODE
    // ==========================
    if (currentMode === "vulnerable") {

        routeBadge.textContent =
            "DISABLED";

        routeBadge.classList.add(
            "high"
        );

        routeMessage.textContent =
            "Dashboard routes can be accessed without authentication checks.";
    }

    // ==========================
    // SECURE MODE
    // ==========================
    if (currentMode === "secure") {

        routeBadge.textContent =
            "ENABLED";

        routeBadge.classList.add(
            "low"
        );

        routeMessage.textContent =
            "Authentication is required before accessing protected routes.";
    }
}

// ==========================
// ROLE AUTHORIZATION UI
// ==========================
export function renderRoleDisplay() {

    const roleBadge =
        document.getElementById(
            "roleBadge"
        );

    const roleDisplay =
        document.getElementById(
            "roleDisplay"
        );

    const roleMessage =
        document.getElementById(
            "roleMessage"
        );

    if (
        !roleBadge ||
        !roleDisplay ||
        !roleMessage
    ) {
        return;
    }

    const role =
        localStorage.getItem(
            "userRole"
        ) || "guest";

    // Reset previous classes
    roleBadge.classList.remove(
        "critical",
        "medium",
        "low"
    );

    roleDisplay.textContent =
        role;

    // ==========================
    // ADMIN
    // ==========================
    if (role === "admin") {

        roleBadge.textContent =
            "ADMIN";

        roleBadge.classList.add(
            "critical"
        );

        roleMessage.textContent =
            "Full administrative access granted.";
    }

    // ==========================
    // ANALYST
    // ==========================
    if (role === "analyst") {

        roleBadge.textContent =
            "ANALYST";

        roleBadge.classList.add(
            "medium"
        );

        roleMessage.textContent =
            "Security analysis permissions granted.";
    }

    // ==========================
    // USER
    // ==========================
    if (role === "user") {

        roleBadge.textContent =
            "USER";

        roleBadge.classList.add(
            "low"
        );

        roleMessage.textContent =
            "Limited dashboard access granted.";
    }

    // ==========================
    // GUEST
    // ==========================
    if (role === "guest") {

        roleBadge.textContent =
            "GUEST";

        roleBadge.classList.add(
            "medium"
        );

        roleMessage.textContent =
            "No authenticated role assigned.";
    }
}

// ==========================
// SESSION METADATA UI
// ==========================
export function renderSessionMetadata(
    getSessionMode
) {

    const sessionModeDisplay =
        document.getElementById(
            "sessionModeDisplay"
        );

    const sessionRoleDisplay =
        document.getElementById(
            "sessionRoleDisplay"
        );

    if (
        !sessionModeDisplay ||
        !sessionRoleDisplay
    ) {
        return;
    }

    const sessionMode =
        getSessionMode();

    const userRole =
        localStorage.getItem(
            "userRole"
        ) || "guest";

    sessionModeDisplay.textContent =
        sessionMode;

    sessionRoleDisplay.textContent =
        userRole;
}

// ==========================
// JWT DISPLAY UI
// ==========================
export function renderJwtDisplay() {

    const jwtDisplay =
        document.getElementById(
            "jwtDisplay"
        );

    if (!jwtDisplay) {
        return;
    }

    const role =
        localStorage.getItem(
            "userRole"
        ) || "guest";

    const payload = {
        role: role
    };

    jwtDisplay.textContent =
        JSON.stringify(
            payload,
            null,
            4
        );
}

// ==========================
// SESSION TIMELINE UI
// ==========================
export function renderSessionTimeline(
    getSessionMode,
    getSessionId
) {

    const sessionTimeline =
        document.getElementById(
            "sessionTimeline"
        );

    if (!sessionTimeline) {
        return;
    }

    sessionTimeline.innerHTML = "";

    const currentMode =
        getSessionMode();

    const activeSession =
        getSessionId();

    const events = [];

    // Exploit simulation
    if (
        activeSession ===
        "attacker-session-123"
    ) {

        events.push(
            "🎯 Attacker fixed the session ID before login."
        );
    }

    // Vulnerable flow
    if (currentMode === "vulnerable") {

        events.push(
            "🔴 Application reused existing session after login."
        );

        events.push(
            "⚠️ Session was NOT regenerated."
        );

        events.push(
            "💥 Attacker may hijack authenticated session."
        );
    }

    // Secure flow
    if (currentMode === "secure") {

        events.push(
            "🟢 Application regenerated session after login."
        );

        events.push(
            "✅ Previously fixed session became invalid."
        );

        events.push(
            "🔒 Session fixation attack prevented."
        );
    }

    // Render events
    events.forEach(event => {

        const li =
            document.createElement("li");

        li.innerHTML =
            `<strong>Event:</strong> ${event}`;

        sessionTimeline.appendChild(li);
    });
}

// ==========================
// LOCKOUT COUNTDOWN UI
// ==========================
export function initializeLockoutCountdown(
    isLockedOut,
    getRemainingLockTime
) {

    const lockoutMessage =
        document.getElementById(
            "lockoutMessage"
        );

    if (!lockoutMessage) {
        return;
    }

    setInterval(() => {

        if (isLockedOut()) {

            const remaining =
                getRemainingLockTime();

            showMessage(
                lockoutMessage,
                `Too many failed attempts. Try again in ${remaining}s.`,
                "#f87171"
            );

        } else {

            showMessage(
                lockoutMessage,
                "",
                "transparent"
            );
        }

    }, 1000);
}