(() => {
  'use strict';

  const key = 'vscanner.vehicle.theme';
  const readTheme = () => {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  };
  const apply = (choice) => {
    const theme = choice === 'cinematic' ? 'cinematic' : 'paper';
    document.documentElement.dataset.theme = theme;
    document.querySelector('meta[name="theme-color"]').content = theme === 'cinematic' ? '#0a0d12' : '#f7f4ed';
    return theme;
  };

  const initialTheme = apply(readTheme());
  document.addEventListener('DOMContentLoaded', () => {
    const select = document.getElementById('themeSelect');
    select.value = initialTheme;
    select.addEventListener('change', () => {
      const theme = apply(select.value);
      try {
        localStorage.setItem(key, theme);
      } catch {
        // Theme still applies to the current page when browser storage is unavailable.
      }
    });
  }, { once: true });
})();
