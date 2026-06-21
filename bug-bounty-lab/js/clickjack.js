// ===========================================================
// Clickjacking Demo
// ===========================================================

function hiddenAction() {
    alert("⚠️ You just clicked a hidden action!");
}

function safeAction() {
    alert("✅ Safe: You clicked the real button");
}