// ===========================================================
// Tab Navigation
// ===========================================================

const navItems =
    document.querySelectorAll(".nav-item");

const tabSections =
    document.querySelectorAll(".tab-section");

// ===========================================================
// Navigation Logic
// ===========================================================

navItems.forEach(item => {

    item.addEventListener("click", () => {

        const targetTab =
            item.dataset.tab;

        resetNavigation();

        item.classList.add("active");

        showTab(targetTab);
    });
});

// ===========================================================
// Helpers
// ===========================================================

function resetNavigation() {

    navItems.forEach(item => {

        item.classList.remove("active");
    });

    tabSections.forEach(section => {

        section.classList.add("hidden");
    });
}

function showTab(tabId) {

    const targetSection =
        document.getElementById(tabId);

    if (!targetSection) return;

    targetSection.classList.remove("hidden");
}