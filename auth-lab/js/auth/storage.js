// ==========================
// STORAGE KEYS
// ==========================
const LOGIN_KEY = "isLoggedIn";
const SESSION_KEY = "sessionId";

// ==========================
// LOGIN SESSION
// ==========================
export function setLoginSession() {
    localStorage.setItem(LOGIN_KEY, "true");
}

export function removeLoginSession() {
    localStorage.removeItem(LOGIN_KEY);
}

export function hasLoginSession() {
    return localStorage.getItem(LOGIN_KEY) === "true";
}

// ==========================
// SESSION ID MANAGEMENT
// ==========================
export function setSessionId(sessionId) {
    localStorage.setItem(SESSION_KEY, sessionId);
}

export function getSessionId() {
    return localStorage.getItem(SESSION_KEY);
}

export function removeSessionId() {
    localStorage.removeItem(SESSION_KEY);
}

// ==========================
// SESSION SECURITY MODE
// ==========================
const SESSION_MODE_KEY = "sessionMode";

export function setSessionMode(mode) {
    localStorage.setItem(SESSION_MODE_KEY, mode);
}

export function getSessionMode() {
    return localStorage.getItem(SESSION_MODE_KEY);
}