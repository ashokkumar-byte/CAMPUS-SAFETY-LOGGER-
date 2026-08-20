document.addEventListener("DOMContentLoaded", () => {
    const flashes = document.querySelectorAll(".flash");
    if (flashes.length) {
        setTimeout(() => {
            flashes.forEach((item) => {
                item.style.transition = "opacity .4s";
                item.style.opacity = "0";
            });
        }, 4500);
    }
});
