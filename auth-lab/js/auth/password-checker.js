export function analyzePasswordStrength(password) {

    let score = 0;
    const feedback = [];

    // Length check
    if (password.length >= 8) {
        score++;
    } else {
        feedback.push("Password should be at least 8 characters.");
    }

    // Uppercase check
    if (/[A-Z]/.test(password)) {
        score++;
    } else {
        feedback.push("Add at least one uppercase letter.");
    }

    // Number check
    if (/[0-9]/.test(password)) {
        score++;
    } else {
        feedback.push("Add at least one number.");
    }

    // Special character check
    if (/[^A-Za-z0-9]/.test(password)) {
        score++;
    } else {
        feedback.push("Add at least one special character.");
    }

    // Strength levels
    if (score <= 1) {
        return {
            strength: "Weak",
            className: "weak",
            feedback
        };
    }

    if (score <= 3) {
        return {
            strength: "Moderate",
            className: "medium",
            feedback
        };
    }

    return {
        strength: "Strong",
        className: "strong",
        feedback
    };
}