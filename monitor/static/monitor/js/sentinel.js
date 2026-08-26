/**
 * IML Sentinel Guard — Futuristic Theme & Client Interactions Engine
 */

(function () {
  'use strict';

  // 1. Theme Management System
  const STORAGE_KEY = 'iml_sentinel_theme';

  function getPreferredTheme() {
    const savedTheme = localStorage.getItem(STORAGE_KEY);
    if (savedTheme) {
      return savedTheme;
    }
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);

    // Update all theme toggle buttons on page
    const toggleBtns = document.querySelectorAll('.theme-toggle-btn');
    toggleBtns.forEach((btn) => {
      const icon = btn.querySelector('i');
      if (icon) {
        if (theme === 'light') {
          icon.className = 'fa-solid fa-moon';
          btn.setAttribute('title', 'Switch to Cyber Dark Mode');
        } else {
          icon.className = 'fa-solid fa-sun';
          btn.setAttribute('title', 'Switch to Quantum Light Mode');
        }
      }
    });

    // Dispatch global event for charts & custom renderers
    window.dispatchEvent(new CustomEvent('sentinel:themeChange', { detail: { theme } }));
  }

  function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(nextTheme);
  }

  // Initialize theme immediately to prevent flashing
  const initialTheme = getPreferredTheme();
  applyTheme(initialTheme);

  document.addEventListener('DOMContentLoaded', () => {
    // Re-apply to sync buttons rendered in DOM
    applyTheme(getPreferredTheme());

    // Bind theme toggle clicks
    document.querySelectorAll('.theme-toggle-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        toggleTheme();
      });
    });

    // 2. Client-side Table Search & Filter
    const searchInputs = document.querySelectorAll('[data-table-search]');
    searchInputs.forEach((input) => {
      const targetTableId = input.getAttribute('data-table-search');
      const table = document.getElementById(targetTableId);
      if (!table) return;

      input.addEventListener('input', () => {
        const query = input.value.toLowerCase().trim();
        const rows = table.querySelectorAll('tbody tr:not(.no-filter)');
        rows.forEach((row) => {
          const text = row.textContent.toLowerCase();
          row.style.display = text.includes(query) ? '' : 'none';
        });
      });
    });

    // Table Severity Filter Buttons
    const filterButtons = document.querySelectorAll('[data-severity-filter]');
    filterButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const filterVal = btn.getAttribute('data-severity-filter');
        const targetTableId = btn.getAttribute('data-target-table');
        const table = document.getElementById(targetTableId);
        if (!table) return;

        // Toggle active button style
        btn.parentElement.querySelectorAll('.filter-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');

        const rows = table.querySelectorAll('tbody tr:not(.no-filter)');
        rows.forEach((row) => {
          if (filterVal === 'ALL') {
            row.style.display = '';
          } else {
            const rowSeverity = row.getAttribute('data-severity') || '';
            row.style.display = rowSeverity.toUpperCase() === filterVal.toUpperCase() ? '' : 'none';
          }
        });
      });
    });

    // 3. One-Click Copy IP Address
    document.querySelectorAll('.copy-ip-btn').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const ip = btn.getAttribute('data-ip');
        if (!ip) return;

        try {
          await navigator.clipboard.writeText(ip);
          const icon = btn.querySelector('i');
          const originalClass = icon ? icon.className : 'fa-regular fa-copy';
          if (icon) icon.className = 'fa-solid fa-check';
          btn.style.color = 'var(--accent-emerald)';

          setTimeout(() => {
            if (icon) icon.className = originalClass;
            btn.style.color = '';
          }, 1500);
        } catch (err) {
          console.error('Failed to copy IP', err);
        }
      });
    });

    // 4. Animated Number Counters
    const counters = document.querySelectorAll('.animate-counter');
    counters.forEach((counter) => {
      const target = parseFloat(counter.getAttribute('data-target') || counter.innerText);
      if (isNaN(target)) return;

      let start = 0;
      const duration = 800; // ms
      const startTime = performance.now();
      const isDecimal = String(counter.getAttribute('data-target') || '').includes('.');

      function updateNumber(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const current = start + (target - start) * (1 - Math.pow(1 - progress, 3)); // ease-out-cubic
        counter.innerText = isDecimal ? current.toFixed(1) : Math.floor(current);

        if (progress < 1) {
          requestAnimationFrame(updateNumber);
        } else {
          counter.innerText = isDecimal ? target.toFixed(1) : target;
        }
      }

      requestAnimationFrame(updateNumber);
    });
  });

  // Expose global helper for Plotly layout generator
  window.SentinelTheme = {
    getCurrentTheme: () => document.documentElement.getAttribute('data-theme') || 'dark',
    getChartLayout: () => {
      const isDark = (document.documentElement.getAttribute('data-theme') || 'dark') === 'dark';
      return {
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: {
          color: isDark ? '#94a3b8' : '#475569',
          family: "'Plus Jakarta Sans', sans-serif",
          size: 11
        },
        margin: { t: 30, r: 30, b: 50, l: 100 },
        xaxis: {
          gridcolor: isDark ? 'rgba(51, 65, 85, 0.4)' : 'rgba(226, 232, 240, 0.9)',
          zerolinecolor: isDark ? 'rgba(51, 65, 85, 0.4)' : 'rgba(226, 232, 240, 0.9)',
          tickfont: { color: isDark ? '#94a3b8' : '#475569' }
        },
        yaxis: {
          gridcolor: isDark ? 'rgba(51, 65, 85, 0.4)' : 'rgba(226, 232, 240, 0.9)',
          zerolinecolor: isDark ? 'rgba(51, 65, 85, 0.4)' : 'rgba(226, 232, 240, 0.9)',
          tickfont: { color: isDark ? '#94a3b8' : '#475569' }
        }
      };
    }
  };
})();
