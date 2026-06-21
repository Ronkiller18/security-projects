/* ============================================
   learn.js — Documentation page interactions
   ============================================ */

// ---- Copy button logic ----
document.querySelectorAll(".copy-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        const targetId = btn.getAttribute("data-target");
        const codeEl   = document.getElementById(targetId);
        if (!codeEl) return;

        navigator.clipboard.writeText(codeEl.innerText).then(() => {
            const originalText = btn.textContent.trim();

            btn.textContent = "Copied!";
            btn.classList.add("copy-btn--success");

            setTimeout(() => {
                btn.textContent = originalText;
                btn.classList.remove("copy-btn--success");
            }, 2000);
        });
    });
});

// ---- TOC active link tracking on scroll ----
const sections = document.querySelectorAll(".doc-section");
const tocLinks = document.querySelectorAll(".toc-link");

const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            tocLinks.forEach(l => l.classList.remove("active"));
            const active = document.querySelector(`.toc-link[href="#${entry.target.id}"]`);
            if (active) active.classList.add("active");
        }
    });
}, { rootMargin: "-20% 0px -70% 0px" });

sections.forEach(s => observer.observe(s));