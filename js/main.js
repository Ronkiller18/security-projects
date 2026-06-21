document.querySelectorAll(".card").forEach(card => {
    card.addEventListener("mousemove", () => {
        card.style.transition = "0.15s";
    });
});