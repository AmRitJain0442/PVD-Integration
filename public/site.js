const revealTargets = document.querySelectorAll("[data-reveal]");

init();

function init() {
  initRevealObserver();
}

function initRevealObserver() {
  if (!("IntersectionObserver" in window)) {
    for (const target of revealTargets) {
      target.classList.add("is-visible");
    }
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      }
    },
    { threshold: 0.12 }
  );

  for (const target of revealTargets) {
    observer.observe(target);
  }
}
