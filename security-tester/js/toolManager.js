// ============================================================
// toolManager.js — Tab switching between tool panels
// ============================================================

const TOOL_BUTTON_SELECTOR = ".tool-tab";
const TOOL_PANEL_SELECTOR  = ".tool-workspace";


export function initializeToolManager() {
    const toolButtons = document.querySelectorAll(TOOL_BUTTON_SELECTOR);

    toolButtons.forEach(button => {
        button.addEventListener("click", () => {
            activateTool(button.dataset.tool);
        });
    });
}

// Exposed so tools can programmatically switch tabs if needed
export function activateTool(toolName) {
    updateToolButtons(toolName);
    updateToolPanels(toolName);
}

function updateToolButtons(toolName) {
    document.querySelectorAll(TOOL_BUTTON_SELECTOR).forEach(button => {
        const isActive = button.dataset.tool === toolName;
        button.classList.toggle("active", isActive);
        button.setAttribute("aria-selected", isActive);
    });
}

function updateToolPanels(toolName) {
    document.querySelectorAll(TOOL_PANEL_SELECTOR).forEach(panel => {
        panel.classList.toggle("active", panel.dataset.toolPanel === toolName);
    });
}