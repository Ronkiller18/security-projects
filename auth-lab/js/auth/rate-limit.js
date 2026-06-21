// ==========================
// RATE LIMIT CONFIG
// ==========================
const MAX_ATTEMPTS = 3;

const LOCKOUT_DURATION = 30000;

// ==========================
// STORAGE KEYS
// ==========================
const FAILED_ATTEMPTS_KEY =
    "failedLoginAttempts";

const LOCKOUT_TIME_KEY =
    "lockoutExpiration";

// ==========================
// GET FAILED ATTEMPTS
// ==========================
export function getFailedAttempts() {

    return Number(
        localStorage.getItem(
            FAILED_ATTEMPTS_KEY
        )
    ) || 0;
}

// ==========================
// INCREMENT FAILED ATTEMPTS
// ==========================
export function incrementFailedAttempts() {

    const attempts =
        getFailedAttempts() + 1;

    localStorage.setItem(
        FAILED_ATTEMPTS_KEY,
        attempts
    );

    // Lock account
    if (attempts >= MAX_ATTEMPTS) {

        const expiration =
            Date.now() + LOCKOUT_DURATION;

        localStorage.setItem(
            LOCKOUT_TIME_KEY,
            expiration
        );
    }
}

// ==========================
// RESET FAILED ATTEMPTS
// ==========================
export function resetFailedAttempts() {

    localStorage.removeItem(
        FAILED_ATTEMPTS_KEY
    );

    localStorage.removeItem(
        LOCKOUT_TIME_KEY
    );
}

// ==========================
// CHECK LOCK STATUS
// ==========================
export function isLockedOut() {

    const expiration =
        Number(
            localStorage.getItem(
                LOCKOUT_TIME_KEY
            )
        );

    if (!expiration) {
        return false;
    }

    // Lock expired
    if (Date.now() > expiration) {

        resetFailedAttempts();

        return false;
    }

    return true;
}

// ==========================
// GET REMAINING LOCK TIME
// ==========================
export function getRemainingLockTime() {

    const expiration =
        Number(
            localStorage.getItem(
                LOCKOUT_TIME_KEY
            )
        );

    if (!expiration) {
        return 0;
    }

    return Math.ceil(
        (expiration - Date.now()) / 1000
    );
}