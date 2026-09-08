/* SecureAuth motion system: progressive enhancement with reduced-motion support. */
(function () {
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches ||
    document.documentElement.classList.contains('pref-reduce-motion');
  const root = document.documentElement;
  const progress = document.querySelector('.scroll-progress span');

  if (reduceMotion) {
    root.classList.add('motion-reduced');
    return;
  }

  root.classList.add('motion-enabled');
  requestAnimationFrame(() => requestAnimationFrame(() => root.classList.add('page-loaded')));

  const revealGroups = [
    '.experience-strip', '.feature-card', '.principle-bar',
    '.security-score-card', '.why-protected-card', '.protection-card',
    '.workspace-card', '.settings-card', '.setup-card', '.timeline-item'
  ];
  const revealItems = [...document.querySelectorAll(revealGroups.join(','))];
  revealItems.forEach((item, index) => {
    item.classList.add('motion-reveal');
    item.style.setProperty('--reveal-delay', `${Math.min(index % 4, 3) * 65}ms`);
  });

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.1, rootMargin: '0px 0px -28px' });
    revealItems.forEach(item => observer.observe(item));
  } else {
    revealItems.forEach(item => item.classList.add('is-visible'));
  }

  let scrollTicking = false;
  function updateProgress() {
    const max = document.documentElement.scrollHeight - window.innerHeight;
    const value = max > 0 ? Math.min(window.scrollY / max, 1) : 0;
    if (progress) progress.style.transform = `scaleX(${value})`;
    scrollTicking = false;
  }
  window.addEventListener('scroll', () => {
    if (!scrollTicking) {
      requestAnimationFrame(updateProgress);
      scrollTicking = true;
    }
  }, { passive: true });
  updateProgress();

  const preview = document.querySelector('.security-preview');
  if (preview && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
    preview.addEventListener('pointermove', (event) => {
      const rect = preview.getBoundingClientRect();
      preview.style.setProperty('--tilt-x', `${((event.clientY - rect.top) / rect.height - .5) * -3}deg`);
      preview.style.setProperty('--tilt-y', `${((event.clientX - rect.left) / rect.width - .5) * 4}deg`);
    });
    preview.addEventListener('pointerleave', () => {
      preview.style.setProperty('--tilt-x', '0deg');
      preview.style.setProperty('--tilt-y', '0deg');
    });
  }
})();
