// ===========================================================
// XSS Demo
// ===========================================================

// ===========================================================
// State
// ===========================================================

let comments = [];

let safeComments = [];

// ===========================================================
// Elements
// ===========================================================

const elements = {

    commentInput:
        document.getElementById("commentInput"),

    safeInput:
        document.getElementById("safeInput"),

    comments:
        document.getElementById("comments"),

    safeComments:
        document.getElementById("safeComments"),

    payloadSelector:
        document.getElementById("payloadSelector"),

    runButton:
        document.getElementById("runXSSBtn"),

    clearButton:
        document.getElementById("clearOutputBtn"),

    message:
        document.getElementById("xssMessage"),

    explanation:
        document.getElementById("xssExplanation"),

    attackStatus:
        document.getElementById("attackStatus")
};

// ===========================================================
// Helpers
// ===========================================================

function updateStatus(message) {

    if (elements.attackStatus) {

        elements.attackStatus.textContent =
            message;
    }
}

function updateMessage(message) {

    if (elements.message) {

        elements.message.textContent =
            message;
    }
}

function updateExplanation(message) {

    if (elements.explanation) {

        elements.explanation.textContent =
            message;
    }
}

function clearElement(element) {

    if (element) {
        element.innerHTML = "";
    }
}

// ===========================================================
// Vulnerable XSS Demo
// ===========================================================

function addComment() {

    const value =
        elements.commentInput?.value;

    if (!value) return;

    comments.push(value);

    displayComments();
}

function displayComments() {

    if (!elements.comments) return;

    let html = "";

    comments.forEach(comment => {

        html += `<p>${comment}</p>`;
    });

    // 🚨 Vulnerable
    elements.comments.innerHTML = html;
}

// ===========================================================
// Safe XSS Demo
// ===========================================================

function addSafeComment() {

    const value =
        elements.safeInput?.value;

    if (!value || !elements.safeComments) return;

    safeComments.push(value);

    displaySafeComments();
}

function displaySafeComments() {

    clearElement(elements.safeComments);

    safeComments.forEach(comment => {

        const paragraph =
            document.createElement("p");

        // ✅ Safe
        paragraph.textContent = comment;

        elements.safeComments.appendChild(
            paragraph
        );
    });
}

// ===========================================================
// Payload Selection
// ===========================================================

if (elements.payloadSelector) {

    elements.payloadSelector.addEventListener(
        "change",
        () => {

            const selectedPayload =
                payloadLibrary[
                    elements.payloadSelector.value
                ];

            if (!selectedPayload) {

                elements.commentInput.value = "";

                updateExplanation("");

                updateMessage("");

                updateStatus("⚪ Idle");

                return;
            }

            elements.commentInput.value =
                selectedPayload.payload;

            updateExplanation(
                selectedPayload.description
            );

            updateMessage(
                `✅ ${selectedPayload.name} loaded`
            );

            updateStatus("⚪ Ready");
        }
    );
}

// ===========================================================
// Run Payload
// ===========================================================

if (elements.runButton) {

    elements.runButton.addEventListener(
        "click",
        () => {

            const value =
                elements.commentInput?.value.trim();

            if (!value) {

                updateStatus("⚪ Idle");

                updateMessage(
                    "⚠️ No payload loaded"
                );

                return;
            }

            addComment();

            updateStatus("🟢 Executed");

            updateMessage(
                "🔥 Attack executed. Check output."
            );
        }
    );
}

// ===========================================================
// Clear Output
// ===========================================================

if (elements.clearButton) {

    elements.clearButton.addEventListener(
        "click",
        clearXSSDemo
    );
}

function clearXSSDemo() {

    comments = [];

    if (elements.commentInput) {
        elements.commentInput.value = "";
    }

    clearElement(elements.comments);

    updateMessage("");

    updateExplanation("");

    updateStatus("⚪ Ready");

    if (elements.payloadSelector) {
        elements.payloadSelector.value = "";
    }
}