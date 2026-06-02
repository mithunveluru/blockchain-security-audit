// SOC dashboard initialization - no GSAP, no floating animations
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-view]').forEach(btn => {
    btn.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        btn.click();
      }
    });
  });
});
