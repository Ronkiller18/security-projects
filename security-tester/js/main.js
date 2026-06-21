// ============================================================
// Import
// ============================================================

import { initializeToolManager }   from "./toolManager.js";
import { initializeScannerTool }   from "./tools/scannerTool.js";
import { initializeJWTTool }       from "./tools/jwtTool.js";
import { initializeCSPTool }       from "./tools/cspTool.js";
import { initializeHeaderTool }    from "./tools/headerTool.js";
import { initializeCookieTool }    from "./tools/cookieTool.js";
import { initializeStorageTool }   from "./tools/storageTool.js";
import { initializeActivityPanel } from "./activityPanel.js";
import { initializeExport }        from "./export.js";
import { clearDashboard }          from "./dashboard.js";

// ============================================================
// App bootstrap
// ============================================================

document.addEventListener("DOMContentLoaded", () => {
    initializeToolManager();
    initializeScannerTool();
    initializeJWTTool();
    initializeCSPTool();
    initializeHeaderTool();
    initializeCookieTool();
    initializeStorageTool();    
    initializeActivityPanel();
    initializeExport();
    initializeClearButton();
});

// ============================================================
// Clear button
// ============================================================

function initializeClearButton() {
    const button = document.getElementById("clearBtn");
    if (!button) return;
    button.addEventListener("click", clearDashboard);
}