# UI Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Revamp the GHP web UI with an earthy color palette (from the octobear logo), teal accents, light/dark mode, token cards for users, token table for admins, guided stepper for token creation, and removal of audit log from the UI.

**Architecture:** All UI is Go `html/template` with `//go:embed`. CSS uses custom properties for theming (light default, dark via `[data-theme="dark"]` and `prefers-color-scheme`). JavaScript is vanilla with Web Components. A new shared CSS file (`theme.css`) provides the design system. Each template links to it instead of duplicating inline styles. A shared `ghp-stepper.js` Web Component handles the multi-step token creation dialog.

**Tech Stack:** Go 1.24, `html/template`, `embed.FS`, vanilla JS, Web Components (Shadow DOM), CSS custom properties. No build tools.

**Design doc:** `docs/plans/2026-02-25-ui-redesign-design.md`

---

## Task 1: Add octobear logo to static assets

**Files:**
- Copy: `assets/octobear.png` -> `internal/web/static/octobear.png`

**Step 1: Copy the octobear image into the embedded static directory**

```bash
cp assets/octobear.png internal/web/static/octobear.png
```

**Step 2: Verify the binary builds with the new asset**

Run: `go build ./...`
Expected: Clean build, no errors.

**Step 3: Commit**

```bash
git add internal/web/static/octobear.png
git commit -m "feat(ui): add octobear logo to embedded static assets"
```

---

## Task 2: Create shared theme CSS file

**Files:**
- Create: `internal/web/static/theme.css`

This file defines ALL design tokens as CSS custom properties and provides base styles shared across all templates. Light mode is the default (`:root`), dark mode is activated via `[data-theme="dark"]` attribute or `prefers-color-scheme: dark` media query.

**Step 1: Create the theme CSS file**

```css
/* ── Theme: design tokens ─────────────────────────────────────── */
:root {
  /* Light mode (default) */
  --color-bg:           #f5f0eb;
  --color-surface:      #ffffff;
  --color-border:       #d9cfc7;
  --color-border-subtle:#e8e0d8;
  --color-text:         #2a1f1a;
  --color-text-secondary:#7a6b5e;
  --color-text-heading: #1a1210;
  --color-accent:       #1a9a87;
  --color-accent-hover: #158575;
  --color-accent-text:  #ffffff;
  --color-danger:       #c53030;
  --color-danger-hover: #a82828;
  --color-status-active:    #2d8a3e;
  --color-status-active-bg: rgba(45,138,62,0.1);
  --color-status-expired:    #c53030;
  --color-status-expired-bg: rgba(197,48,48,0.1);
  --color-status-revoked:    #9a8a7c;
  --color-status-revoked-bg: rgba(154,138,124,0.1);
  --color-input-bg:     #f5f0eb;
  --color-focus:        #2cb5a0;
  --color-focus-ring:   rgba(44,181,160,0.3);
  --color-overlay:      rgba(26,18,16,0.5);
  --color-warning:      #b45309;

  --shadow-sm:    0 1px 2px rgba(26,18,16,0.06);
  --shadow-md:    0 4px 12px rgba(26,18,16,0.08);
  --shadow-lg:    0 8px 24px rgba(26,18,16,0.12);

  --radius-sm:    6px;
  --radius-md:    10px;
  --radius-lg:    14px;
  --radius-full:  9999px;

  --font-sans:    'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono:    'JetBrains Mono', ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;

  --transition:   150ms ease;
}

/* Dark mode */
[data-theme="dark"] {
  --color-bg:           #1a1210;
  --color-surface:      #2a2220;
  --color-border:       #3d3230;
  --color-border-subtle:#332a28;
  --color-text:         #ede5db;
  --color-text-secondary:#9a8a7c;
  --color-text-heading: #f5f0eb;
  --color-accent:       #2cb5a0;
  --color-accent-hover: #3ccdb5;
  --color-accent-text:  #1a1210;
  --color-danger:       #d94040;
  --color-danger-hover: #e85555;
  --color-status-active:    #3fb950;
  --color-status-active-bg: rgba(63,185,80,0.15);
  --color-status-expired:    #d9534f;
  --color-status-expired-bg: rgba(217,83,79,0.15);
  --color-status-revoked:    #6a5a4e;
  --color-status-revoked-bg: rgba(106,90,78,0.15);
  --color-input-bg:     #1a1210;
  --color-focus:        #2cb5a0;
  --color-focus-ring:   rgba(44,181,160,0.3);
  --color-overlay:      rgba(10,6,4,0.7);
  --color-warning:      #f0883e;

  --shadow-sm:    0 1px 2px rgba(0,0,0,0.2);
  --shadow-md:    0 4px 12px rgba(0,0,0,0.3);
  --shadow-lg:    0 8px 24px rgba(0,0,0,0.4);
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --color-bg:           #1a1210;
    --color-surface:      #2a2220;
    --color-border:       #3d3230;
    --color-border-subtle:#332a28;
    --color-text:         #ede5db;
    --color-text-secondary:#9a8a7c;
    --color-text-heading: #f5f0eb;
    --color-accent:       #2cb5a0;
    --color-accent-hover: #3ccdb5;
    --color-accent-text:  #1a1210;
    --color-danger:       #d94040;
    --color-danger-hover: #e85555;
    --color-status-active:    #3fb950;
    --color-status-active-bg: rgba(63,185,80,0.15);
    --color-status-expired:    #d9534f;
    --color-status-expired-bg: rgba(217,83,79,0.15);
    --color-status-revoked:    #6a5a4e;
    --color-status-revoked-bg: rgba(106,90,78,0.15);
    --color-input-bg:     #1a1210;
    --color-focus:        #2cb5a0;
    --color-focus-ring:   rgba(44,181,160,0.3);
    --color-overlay:      rgba(10,6,4,0.7);
    --color-warning:      #f0883e;

    --shadow-sm:    0 1px 2px rgba(0,0,0,0.2);
    --shadow-md:    0 4px 12px rgba(0,0,0,0.3);
    --shadow-lg:    0 8px 24px rgba(0,0,0,0.4);
  }
}

/* ── Base resets ──────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font-sans);
  font-size: 15px;
  line-height: 1.5;
  color: var(--color-text);
  background: var(--color-bg);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* ── Layout ──────────────────────────────────────────────────── */
.container {
  max-width: 1100px;
  margin: 0 auto;
  padding: 1.5rem;
}

/* ── Header ──────────────────────────────────────────────────── */
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 0;
  border-bottom: 1px solid var(--color-border);
  margin-bottom: 2rem;
}

.header-brand {
  display: flex;
  align-items: center;
  gap: 0.625rem;
  text-decoration: none;
  color: var(--color-text-heading);
}

.header-brand img {
  width: 32px;
  height: 32px;
}

.header-brand span {
  font-size: 1.25rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}

.header-brand .badge-admin {
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--color-text-secondary);
  margin-left: 0.25rem;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.header-actions .username {
  font-size: 0.875rem;
  color: var(--color-text-secondary);
}

/* ── Buttons ─────────────────────────────────────────────────── */
.btn {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.5rem 1rem;
  border-radius: var(--radius-sm);
  font-family: var(--font-sans);
  font-size: 0.875rem;
  font-weight: 600;
  line-height: 1.4;
  text-decoration: none;
  border: 1px solid transparent;
  cursor: pointer;
  transition: background var(--transition), border-color var(--transition), color var(--transition);
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-primary {
  background: var(--color-accent);
  color: var(--color-accent-text);
  border-color: var(--color-accent);
}

.btn-primary:hover:not(:disabled) {
  background: var(--color-accent-hover);
  border-color: var(--color-accent-hover);
}

.btn-danger {
  background: transparent;
  color: var(--color-danger);
  border-color: var(--color-border);
}

.btn-danger:hover:not(:disabled) {
  background: var(--color-danger);
  color: #fff;
  border-color: var(--color-danger);
}

.btn-ghost {
  background: transparent;
  color: var(--color-text-secondary);
  border-color: var(--color-border);
}

.btn-ghost:hover:not(:disabled) {
  background: var(--color-surface);
  color: var(--color-text);
  border-color: var(--color-border);
}

.btn-lg {
  padding: 0.75rem 1.5rem;
  font-size: 1rem;
}

/* ── Theme toggle ────────────────────────────────────────────── */
.theme-toggle {
  background: none;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  padding: 0.375rem;
  cursor: pointer;
  color: var(--color-text-secondary);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color var(--transition), border-color var(--transition);
}

.theme-toggle:hover {
  color: var(--color-text);
  border-color: var(--color-text-secondary);
}

.theme-toggle svg {
  width: 18px;
  height: 18px;
}

/* ── Sections ────────────────────────────────────────────────── */
.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.25rem;
}

.section-header h2 {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--color-text-heading);
  letter-spacing: -0.01em;
}

/* ── Token cards (user dashboard) ────────────────────────────── */
.token-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: 1rem;
}

.token-card {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  padding: 1.25rem;
  transition: box-shadow var(--transition), border-color var(--transition);
}

.token-card:hover {
  box-shadow: var(--shadow-md);
}

.token-card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.75rem;
}

.token-card-repo {
  font-size: 1rem;
  font-weight: 600;
  color: var(--color-text-heading);
  word-break: break-word;
}

.token-card-prefix {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--color-text-secondary);
}

.token-card-scopes {
  display: flex;
  flex-wrap: wrap;
  gap: 0.375rem;
  margin-bottom: 0.75rem;
}

.scope-chip {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: var(--radius-full);
  font-size: 0.75rem;
  font-family: var(--font-mono);
  background: var(--color-border-subtle);
  color: var(--color-text-secondary);
}

.token-card-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.token-card-meta {
  font-size: 0.8rem;
  color: var(--color-text-secondary);
}

.token-card-session {
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  margin-bottom: 0.5rem;
  font-family: var(--font-mono);
}

/* ── Status indicators ───────────────────────────────────────── */
.status {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  font-size: 0.8rem;
  font-weight: 500;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.status-active .status-dot  { background: var(--color-status-active); }
.status-active              { color: var(--color-status-active); }
.status-expired .status-dot { background: var(--color-status-expired); }
.status-expired             { color: var(--color-status-expired); }
.status-revoked .status-dot { background: var(--color-status-revoked); }
.status-revoked             { color: var(--color-status-revoked); }

/* ── Tables (admin) ──────────────────────────────────────────── */
.table-wrap {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  overflow: hidden;
}

.table-wrap table {
  width: 100%;
  border-collapse: collapse;
}

.table-wrap th,
.table-wrap td {
  padding: 0.75rem 1rem;
  text-align: left;
  font-size: 0.875rem;
  border-bottom: 1px solid var(--color-border-subtle);
}

.table-wrap th {
  font-weight: 600;
  color: var(--color-text-secondary);
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.table-wrap tr:last-child td {
  border-bottom: none;
}

.table-wrap tr:hover td {
  background: var(--color-bg);
}

/* ── Badge (admin tables) ────────────────────────────────────── */
.badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: var(--radius-full);
  font-size: 0.75rem;
  font-weight: 600;
}

.badge-active  { background: var(--color-status-active-bg);  color: var(--color-status-active); }
.badge-expired { background: var(--color-status-expired-bg); color: var(--color-status-expired); }
.badge-revoked { background: var(--color-status-revoked-bg); color: var(--color-status-revoked); }
.badge-proxy   { background: var(--color-border-subtle); color: var(--color-text-secondary); }
.badge-agent   { background: rgba(44,181,160,0.15); color: var(--color-accent); }
.badge-admin   { background: rgba(44,181,160,0.15); color: var(--color-accent); }
.badge-user    { background: var(--color-border-subtle); color: var(--color-text-secondary); }
.badge-dev     { background: rgba(180,83,9,0.15); color: var(--color-warning); }

/* ── Tabs (admin) ────────────────────────────────────────────── */
.tabs {
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--color-border);
  margin-bottom: 1.5rem;
}

.tab {
  padding: 0.75rem 1.25rem;
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--color-text-secondary);
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  transition: color var(--transition), border-color var(--transition);
  font-family: var(--font-sans);
}

.tab:hover {
  color: var(--color-text);
}

.tab.active {
  color: var(--color-accent);
  border-bottom-color: var(--color-accent);
}

.tab-panel {
  display: none;
}

.tab-panel.active {
  display: block;
}

/* ── Filter bar (admin tokens) ───────────────────────────────── */
.filter-bar {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
  align-items: center;
}

.filter-bar select,
.filter-bar input {
  padding: 0.4rem 0.75rem;
  background: var(--color-input-bg);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  color: var(--color-text);
  font-size: 0.8rem;
  font-family: var(--font-sans);
}

.filter-bar select:focus,
.filter-bar input:focus {
  outline: none;
  border-color: var(--color-focus);
  box-shadow: 0 0 0 3px var(--color-focus-ring);
}

/* ── Forms ────────────────────────────────────────────────────── */
.form-group {
  margin-bottom: 1.25rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.375rem;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--color-text-secondary);
}

.form-group input,
.form-group select {
  width: 100%;
  padding: 0.5rem 0.75rem;
  background: var(--color-input-bg);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  color: var(--color-text);
  font-size: 0.875rem;
  font-family: var(--font-sans);
  transition: border-color var(--transition), box-shadow var(--transition);
}

.form-group select {
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%239a8a7c' d='M6 8.825a.5.5 0 0 1-.354-.146l-3.5-3.5a.5.5 0 1 1 .708-.708L6 7.618l3.146-3.147a.5.5 0 1 1 .708.708l-3.5 3.5A.5.5 0 0 1 6 8.825z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 0.625rem center;
  padding-right: 2rem;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: var(--color-focus);
  box-shadow: 0 0 0 3px var(--color-focus-ring);
}

/* ── Token display (post-creation) ───────────────────────────── */
.token-display {
  background: var(--color-input-bg);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  padding: 1rem;
  font-family: var(--font-mono);
  font-size: 0.875rem;
  word-break: break-all;
  color: var(--color-text);
}

.token-warning {
  color: var(--color-warning);
  font-size: 0.8rem;
  margin-top: 0.5rem;
}

/* ── Empty state ─────────────────────────────────────────────── */
.empty-state {
  text-align: center;
  padding: 3rem 1rem;
  color: var(--color-text-secondary);
}

.empty-state img {
  width: 80px;
  height: 80px;
  opacity: 0.4;
  margin-bottom: 1rem;
}

.empty-state p {
  margin-bottom: 1rem;
  font-size: 0.95rem;
}

/* ── Modal / Stepper dialog ──────────────────────────────────── */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: var(--color-overlay);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  opacity: 0;
  visibility: hidden;
  transition: opacity var(--transition), visibility var(--transition);
}

.modal-overlay.open {
  opacity: 1;
  visibility: visible;
}

.modal {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  width: 100%;
  max-width: 520px;
  max-height: 90vh;
  overflow-y: auto;
  padding: 2rem;
}

.stepper-dots {
  display: flex;
  justify-content: center;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
}

.stepper-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--color-border);
  transition: background var(--transition);
}

.stepper-dot.active {
  background: var(--color-accent);
}

.stepper-dot.completed {
  background: var(--color-accent);
  opacity: 0.5;
}

.stepper-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: var(--color-text-heading);
  margin-bottom: 1.25rem;
}

.stepper-actions {
  display: flex;
  justify-content: space-between;
  margin-top: 1.5rem;
  gap: 0.75rem;
}

.stepper-step {
  display: none;
}

.stepper-step.active {
  display: block;
}

/* ── Link style ──────────────────────────────────────────────── */
a.link {
  color: var(--color-accent);
  text-decoration: none;
}

a.link:hover {
  text-decoration: underline;
}

/* ── Utilities ───────────────────────────────────────────────── */
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0,0,0,0);
  white-space: nowrap;
  border: 0;
}

.text-mono {
  font-family: var(--font-mono);
}
```

**Step 2: Verify the binary builds**

Run: `go build ./...`
Expected: Clean build (CSS is embedded via `//go:embed static/*`).

**Step 3: Commit**

```bash
git add internal/web/static/theme.css
git commit -m "feat(ui): add shared theme.css with design tokens and component styles"
```

---

## Task 3: Add theme toggle JavaScript

**Files:**
- Create: `internal/web/static/theme.js`

Tiny script that manages the light/dark toggle, respects `prefers-color-scheme` on first visit, and persists the choice to `localStorage`.

**Step 1: Create the theme toggle script**

```javascript
/**
 * Theme management — light/dark mode toggle.
 *
 * On first visit: respects prefers-color-scheme.
 * On toggle: saves to localStorage and sets data-theme on <html>.
 */
(function () {
  const KEY = 'ghp-theme';
  const root = document.documentElement;

  function getSystemTheme() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function apply(theme) {
    root.setAttribute('data-theme', theme);
    // Update toggle button icon if present.
    const btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
      btn.innerHTML = theme === 'dark'
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
    }
  }

  // Initialise.
  const saved = localStorage.getItem(KEY);
  apply(saved || getSystemTheme());

  // Listen for system changes when no explicit preference.
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    if (!localStorage.getItem(KEY)) apply(e.matches ? 'dark' : 'light');
  });

  // Expose toggle for the button.
  window.toggleTheme = function () {
    const current = root.getAttribute('data-theme') || getSystemTheme();
    const next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem(KEY, next);
    apply(next);
  };
})();
```

**Step 2: Verify build**

Run: `go build ./...`
Expected: Clean build.

**Step 3: Commit**

```bash
git add internal/web/static/theme.js
git commit -m "feat(ui): add theme toggle script with localStorage persistence"
```

---

## Task 4: Create the stepper Web Component

**Files:**
- Create: `internal/web/static/ghp-stepper.js`

A reusable `<ghp-stepper>` Web Component that handles the multi-step modal dialog pattern. Used by both user dashboard (4-step) and admin dashboard (5-step) token creation flows.

**Step 1: Create the stepper component**

The component manages:
- Step navigation (next/back) with validation callbacks
- Progress dots
- Open/close with overlay
- Keyboard support (Escape to close)
- A `complete` event when the final step's action succeeds

```javascript
/**
 * <ghp-stepper> — multi-step modal dialog web component.
 *
 * Usage:
 *   const stepper = document.querySelector('ghp-stepper');
 *   stepper.steps = [
 *     { title: 'Repository', validate: () => !!repoSelect.value },
 *     { title: 'Permissions', validate: () => Object.keys(permSelect.value).length > 0 },
 *     { title: 'Details' },
 *     { title: 'Confirm' },
 *   ];
 *   stepper.open();
 *
 * Slots:
 *   <div slot="step-0"> ... </div>
 *   <div slot="step-1"> ... </div>
 *
 * Events:
 *   "close" — dialog closed
 *   "step-change" — step changed, detail: { step: number }
 */
class GhpStepper extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._steps = [];
    this._currentStep = 0;
    this._isOpen = false;
  }

  get steps() { return this._steps; }
  set steps(s) {
    this._steps = s || [];
    this._render();
  }

  get currentStep() { return this._currentStep; }

  open() {
    this._currentStep = 0;
    this._isOpen = true;
    this._render();
    this._updateStepVisibility();
    // Trap focus.
    requestAnimationFrame(() => {
      const overlay = this.shadowRoot.querySelector('.overlay');
      if (overlay) overlay.focus();
    });
  }

  close() {
    this._isOpen = false;
    this._render();
    this.dispatchEvent(new Event('close'));
  }

  next() {
    const step = this._steps[this._currentStep];
    if (step && step.validate && !step.validate()) return false;
    if (this._currentStep < this._steps.length - 1) {
      this._currentStep++;
      this._updateStepVisibility();
      this.dispatchEvent(new CustomEvent('step-change', { detail: { step: this._currentStep } }));
      return true;
    }
    return false;
  }

  back() {
    if (this._currentStep > 0) {
      this._currentStep--;
      this._updateStepVisibility();
      this.dispatchEvent(new CustomEvent('step-change', { detail: { step: this._currentStep } }));
    }
  }

  reset() {
    this._currentStep = 0;
    this._isOpen = false;
    this._render();
  }

  _updateStepVisibility() {
    // Update dots.
    const dots = this.shadowRoot.querySelectorAll('.dot');
    dots.forEach((dot, i) => {
      dot.classList.toggle('active', i === this._currentStep);
      dot.classList.toggle('completed', i < this._currentStep);
    });

    // Update slots.
    const slots = this.shadowRoot.querySelectorAll('.step-slot');
    slots.forEach((slot, i) => {
      slot.style.display = i === this._currentStep ? 'block' : 'none';
    });

    // Update title.
    const title = this.shadowRoot.querySelector('.step-title');
    if (title && this._steps[this._currentStep]) {
      title.textContent = this._steps[this._currentStep].title;
    }

    // Update nav buttons.
    const backBtn = this.shadowRoot.querySelector('.btn-back');
    const nextBtn = this.shadowRoot.querySelector('.btn-next');
    if (backBtn) backBtn.style.visibility = this._currentStep === 0 ? 'hidden' : 'visible';
    if (nextBtn) {
      const isLast = this._currentStep === this._steps.length - 1;
      nextBtn.style.display = isLast ? 'none' : '';
    }
  }

  _render() {
    if (!this._isOpen) {
      this.shadowRoot.innerHTML = '';
      return;
    }

    const dots = this._steps.map((_, i) => `<span class="dot${i === 0 ? ' active' : ''}"></span>`).join('');
    const slotEls = this._steps.map((_, i) => `<div class="step-slot" style="display:${i === 0 ? 'block' : 'none'}"><slot name="step-${i}"></slot></div>`).join('');

    this.shadowRoot.innerHTML = `
      <style>
        :host { display: contents; }
        .overlay {
          position: fixed; inset: 0; z-index: 100;
          background: var(--color-overlay, rgba(26,18,16,0.5));
          backdrop-filter: blur(4px);
          display: flex; align-items: center; justify-content: center;
          outline: none;
        }
        .dialog {
          background: var(--color-surface, #fff);
          border: 1px solid var(--color-border, #d9cfc7);
          border-radius: var(--radius-lg, 14px);
          box-shadow: var(--shadow-lg, 0 8px 24px rgba(0,0,0,0.12));
          width: 100%; max-width: 520px;
          max-height: 90vh; overflow-y: auto;
          padding: 2rem;
        }
        .dots {
          display: flex; justify-content: center; gap: 0.5rem;
          margin-bottom: 1.5rem;
        }
        .dot {
          width: 10px; height: 10px; border-radius: 50%;
          background: var(--color-border, #d9cfc7);
          transition: background 150ms ease;
        }
        .dot.active { background: var(--color-accent, #1a9a87); }
        .dot.completed { background: var(--color-accent, #1a9a87); opacity: 0.5; }
        .step-title {
          font-size: 1.1rem; font-weight: 600;
          color: var(--color-text-heading, #1a1210);
          margin-bottom: 1.25rem;
          font-family: var(--font-sans, sans-serif);
        }
        .nav {
          display: flex; justify-content: space-between;
          margin-top: 1.5rem; gap: 0.75rem;
        }
        button {
          display: inline-flex; align-items: center; gap: 0.375rem;
          padding: 0.5rem 1rem; border-radius: var(--radius-sm, 6px);
          font-family: var(--font-sans, sans-serif);
          font-size: 0.875rem; font-weight: 600;
          border: 1px solid transparent; cursor: pointer;
          transition: background 150ms ease, border-color 150ms ease, color 150ms ease;
        }
        .btn-back {
          background: transparent;
          color: var(--color-text-secondary, #7a6b5e);
          border-color: var(--color-border, #d9cfc7);
        }
        .btn-back:hover { background: var(--color-bg, #f5f0eb); }
        .btn-next {
          background: var(--color-accent, #1a9a87);
          color: var(--color-accent-text, #fff);
          border-color: var(--color-accent, #1a9a87);
        }
        .btn-next:hover { background: var(--color-accent-hover, #158575); }
        .btn-close {
          position: absolute; top: 1rem; right: 1rem;
          background: none; border: none; cursor: pointer;
          color: var(--color-text-secondary, #7a6b5e);
          font-size: 1.25rem; padding: 0.25rem;
        }
        .btn-close:hover { color: var(--color-text, #2a1f1a); }
        .dialog-inner { position: relative; }
      </style>
      <div class="overlay" tabindex="-1">
        <div class="dialog">
          <div class="dialog-inner">
            <button class="btn-close" type="button" aria-label="Close">&times;</button>
            <div class="dots">${dots}</div>
            <div class="step-title">${this._steps[0] ? this._steps[0].title : ''}</div>
            ${slotEls}
            <div class="nav">
              <button class="btn-back" type="button" style="visibility:hidden">Back</button>
              <button class="btn-next" type="button">Next</button>
            </div>
          </div>
        </div>
      </div>
    `;

    // Wire events.
    this.shadowRoot.querySelector('.btn-close').addEventListener('click', () => this.close());
    this.shadowRoot.querySelector('.btn-back').addEventListener('click', () => this.back());
    this.shadowRoot.querySelector('.btn-next').addEventListener('click', () => this.next());
    this.shadowRoot.querySelector('.overlay').addEventListener('keydown', (e) => {
      if (e.key === 'Escape') this.close();
    });
    // Close on overlay click (not dialog click).
    this.shadowRoot.querySelector('.overlay').addEventListener('click', (e) => {
      if (e.target === e.currentTarget) this.close();
    });
  }
}

customElements.define('ghp-stepper', GhpStepper);
```

**Step 2: Verify build**

Run: `go build ./...`
Expected: Clean build.

**Step 3: Commit**

```bash
git add internal/web/static/ghp-stepper.js
git commit -m "feat(ui): add ghp-stepper web component for multi-step dialogs"
```

---

## Task 5: Update `<ghp-repo-select>` to use theme CSS custom properties

**Files:**
- Modify: `internal/web/static/ghp-repo-select.js`

The component uses Shadow DOM so it can't inherit external CSS classes, but it **can** read CSS custom properties from the host document. Replace all hardcoded hex colors with `var(--color-*)` references.

**Step 1: Update the Shadow DOM styles in `connectedCallback`**

Replace the existing `<style>` block (lines 71-108) with one that uses CSS custom properties. Every hardcoded color becomes a `var()` with the old value as fallback.

Key replacements:
- `#21262d` chip bg → `var(--color-border-subtle, #21262d)`
- `#30363d` borders → `var(--color-border, #30363d)`
- `#c9d1d9` text → `var(--color-text, #c9d1d9)`
- `#8b949e` muted → `var(--color-text-secondary, #8b949e)`
- `#0d1117` input bg → `var(--color-input-bg, #0d1117)`
- `#161b22` dropdown bg → `var(--color-surface, #161b22)`
- `#58a6ff` focus → `var(--color-focus, #58a6ff)`
- `rgba(88,166,255,0.3)` focus ring → `var(--color-focus-ring, rgba(88,166,255,0.3))`
- `#f85149` remove hover → `var(--color-danger, #f85149)`
- Font family → `var(--font-sans, ...)`

**Step 2: Verify build**

Run: `go build ./...`
Expected: Clean build.

**Step 3: Commit**

```bash
git add internal/web/static/ghp-repo-select.js
git commit -m "feat(ui): update repo-select component to use theme CSS custom properties"
```

---

## Task 6: Update `<ghp-permission-select>` to use theme CSS custom properties

**Files:**
- Modify: `internal/web/static/ghp-permission-select.js`

Same approach as Task 5. Replace hardcoded colors in the `_styles()` method (lines 131-168) with `var(--color-*)` references.

Key replacements:
- `#30363d` borders → `var(--color-border, #30363d)`
- `#21262d` row separator → `var(--color-border-subtle, #21262d)`
- `#f0f6fc` perm name → `var(--color-text-heading, #f0f6fc)`
- `#8b949e` desc → `var(--color-text-secondary, #8b949e)`
- `#0d1117` select bg → `var(--color-input-bg, #0d1117)`
- `#c9d1d9` select text → `var(--color-text, #c9d1d9)`
- `#58a6ff` focus → `var(--color-focus, #58a6ff)`
- `#484f58` empty → `var(--color-text-secondary, #484f58)`
- Font family → `var(--font-sans, ...)`

**Step 2: Verify build**

Run: `go build ./...`
Expected: Clean build.

**Step 3: Commit**

```bash
git add internal/web/static/ghp-permission-select.js
git commit -m "feat(ui): update permission-select component to use theme CSS custom properties"
```

---

## Task 7: Rewrite `login.html`

**Files:**
- Modify: `internal/web/templates/login.html`

Replace the entire template. The new login page uses `theme.css`, `theme.js`, the octobear logo, and the new design language.

**Step 1: Rewrite the template**

The new template should:
- Link `theme.css` and `theme.js` in `<head>`
- Have minimal page-specific styles (just the centered login card layout)
- Show octobear image at ~120px
- Display "ghp" wordmark and subtitle
- Single teal "Sign in with GitHub" button linking to `/auth/github`
- Warm background with subtle radial gradient

Structure:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ghp — Login</title>
    <link rel="stylesheet" href="/static/theme.css">
    <script src="/static/theme.js"></script>
    <style>
        body {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background:
                radial-gradient(ellipse at 50% 0%, var(--color-border-subtle) 0%, transparent 60%),
                var(--color-bg);
        }
        .login-card {
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-lg);
            padding: 3rem 2.5rem;
            max-width: 400px;
            width: 100%;
            text-align: center;
            box-shadow: var(--shadow-lg);
        }
        .login-logo { width: 120px; height: 120px; margin-bottom: 1.25rem; }
        .login-title {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--color-text-heading);
            margin-bottom: 0.375rem;
            letter-spacing: -0.02em;
        }
        .login-subtitle {
            color: var(--color-text-secondary);
            margin-bottom: 2rem;
            font-size: 0.95rem;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <img src="/static/octobear.png" alt="ghp" class="login-logo">
        <h1 class="login-title">ghp</h1>
        <p class="login-subtitle">GitHub Proxy for Coding Agents</p>
        <a href="/auth/github" class="btn btn-primary btn-lg" style="width:100%">Sign in with GitHub</a>
    </div>
</body>
</html>
```

**Step 2: Verify build**

Run: `go build ./...`
Expected: Clean build.

**Step 3: Commit**

```bash
git add internal/web/templates/login.html
git commit -m "feat(ui): redesign login page with octobear logo and earthy theme"
```

---

## Task 8: Rewrite `admin-login.html`

**Files:**
- Modify: `internal/web/templates/admin-login.html`

Same visual treatment as login, but with the DEV MODE badge, username input, and test-login JS.

**Step 1: Rewrite the template**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ghp — Admin Login (Dev Mode)</title>
    <link rel="stylesheet" href="/static/theme.css">
    <script src="/static/theme.js"></script>
    <style>
        body {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background:
                radial-gradient(ellipse at 50% 0%, var(--color-border-subtle) 0%, transparent 60%),
                var(--color-bg);
        }
        .login-card {
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-lg);
            padding: 3rem 2.5rem;
            max-width: 400px;
            width: 100%;
            text-align: center;
            box-shadow: var(--shadow-lg);
        }
        .login-logo { width: 120px; height: 120px; margin-bottom: 1.25rem; }
        .login-title {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--color-text-heading);
            margin-bottom: 0.375rem;
            letter-spacing: -0.02em;
        }
        .login-subtitle {
            color: var(--color-text-secondary);
            margin-bottom: 2rem;
            font-size: 0.95rem;
        }
        .error {
            color: var(--color-danger);
            font-size: 0.85rem;
            margin-top: 1rem;
            display: none;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <img src="/static/octobear.png" alt="ghp" class="login-logo">
        <h1 class="login-title">ghp <span style="color:var(--color-text-secondary);font-weight:400">/ admin</span></h1>
        <span class="badge badge-dev" style="margin-bottom:1rem;display:inline-block">DEV MODE</span>
        <p class="login-subtitle">Sign in as an admin via test-login</p>
        <div class="form-group" style="text-align:left">
            <label for="username">Username</label>
            <input type="text" id="username" value="admin" placeholder="admin">
        </div>
        <button class="btn btn-primary btn-lg" style="width:100%" onclick="login()">Sign in as Admin</button>
        <div class="error" id="error"></div>
    </div>

    <script>
        async function login() {
            const username = document.getElementById('username').value || 'admin';
            const resp = await fetch('/auth/test-login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username, role: 'admin' }),
            });
            if (resp.ok) {
                window.location.href = '/admin';
            } else {
                const err = document.getElementById('error');
                err.textContent = 'Login failed: ' + resp.statusText;
                err.style.display = 'block';
            }
        }

        document.getElementById('username').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') login();
        });
    </script>
</body>
</html>
```

**Step 2: Verify build**

Run: `go build ./...`
Expected: Clean build.

**Step 3: Commit**

```bash
git add internal/web/templates/admin-login.html
git commit -m "feat(ui): redesign admin-login page with earthy theme"
```

---

## Task 9: Rewrite `dashboard.html` — structure and token cards

**Files:**
- Modify: `internal/web/templates/dashboard.html`

This is the largest change. The new dashboard:
- Links `theme.css`, `theme.js`, and all Web Component scripts
- Has the new header with octobear mark, theme toggle, username, admin link, sign out
- Shows tokens as cards (not a table)
- Has a "New Token" button that opens the stepper
- Removes the audit log section entirely
- Removes the inline create-token form (replaced by stepper)

**Step 1: Rewrite the full template**

The template HTML structure:

```
<header class="header">
  brand (octobear + ghp) | theme-toggle, username, [admin link], sign out
</header>

<section-header>
  <h2>Your Tokens</h2>
  <button>New Token</button>
</section-header>

<div id="token-grid" class="token-grid">
  <!-- JS renders token cards or empty state here -->
</div>

<ghp-stepper id="stepper">
  <div slot="step-0"> repo select </div>
  <div slot="step-1"> permission select </div>
  <div slot="step-2"> duration + session </div>
  <div slot="step-3"> confirm + token display </div>
</ghp-stepper>
```

JavaScript:
- `api()` helper (unchanged)
- `loadUserRepos()` — fetches repos, sets on repo-select component
- `loadTokens()` — fetches `/api/tokens`, renders cards into `#token-grid`
- `revokeToken(id)` — revokes with confirm
- Stepper setup: configures steps with validation, wires the "Create" button in step 4
- `createToken()` — called from step 4, posts to API, shows token, resets stepper
- `esc()` helper
- `logout()`
- `formatExpiry(date)` — human-readable relative time ("Expires in 6h", "Expired 2d ago")

**Step 2: Verify build**

Run: `go build ./...`
Expected: Clean build.

**Step 3: Visual check with dev mode**

If dev mode is available, start the server and verify:
- Header renders with octobear, theme toggle works
- Empty state shows when no tokens
- "New Token" opens stepper
- Stepper steps work (next/back/close)
- Token creation works end-to-end
- Created token appears as a card
- Revoke works

**Step 4: Commit**

```bash
git add internal/web/templates/dashboard.html
git commit -m "feat(ui): redesign user dashboard with token cards and stepper dialog"
```

---

## Task 10: Rewrite `admin.html` — tabs, users table, token table, agent stepper

**Files:**
- Modify: `internal/web/templates/admin.html`

The new admin page:
- Links `theme.css`, `theme.js`, and all Web Component scripts
- Header with octobear mark + "admin" label, Dashboard link, theme toggle, sign out
- Two tabs: "Users" and "Tokens"
- Users tab: table with username, role badge, created date, "View tokens" link
- Tokens tab: filter bar (by user, status) + compact token table + "New Agent Token" button + agent stepper
- Removes audit log entirely

**Step 1: Rewrite the full template**

HTML structure:

```
<header class="header">
  brand (octobear + ghp / admin) | Dashboard link, theme-toggle, username, sign out
</header>

<div class="tabs">
  <button class="tab active" data-tab="users">Users</button>
  <button class="tab" data-tab="tokens">Tokens</button>
</div>

<div id="panel-users" class="tab-panel active">
  <div id="users-list"></div>
</div>

<div id="panel-tokens" class="tab-panel">
  <div class="section-header">
    <div class="filter-bar">
      <select id="filter-status">...</select>
      <span id="filter-user-label"></span>
      <button id="clear-filter" style="display:none">Show all</button>
    </div>
    <button class="btn btn-primary" onclick="openAgentStepper()">New Agent Token</button>
  </div>
  <div id="all-tokens" class="table-wrap"></div>
</div>

<ghp-stepper id="agent-stepper">
  <div slot="step-0"> installation select </div>
  <div slot="step-1"> repo multi-select </div>
  <div slot="step-2"> permissions </div>
  <div slot="step-3"> duration + session </div>
  <div slot="step-4"> confirm + token display </div>
</ghp-stepper>
```

JavaScript:
- `api()` helper
- Tab switching logic
- `loadUsers()` — renders users table, "View tokens" switches to Tokens tab filtered
- `loadAllTokens()` — fetches all tokens, renders table with filter support
- `loadUserTokens(userId, username)` — filters token view
- `renderTokenTable(tokens)` — generates `<table>` with status badges, type badges, revoke buttons
- `revokeToken(id)` — with confirm
- `filterTokens()` — applies status/user filters to loaded tokens
- Agent stepper setup with 5 steps + validation
- `loadInstallations()`, `onInstallationChange()` — same logic as current, wired into stepper
- `createAgentToken()` — called from final stepper step
- `esc()`, `logout()`

**Step 2: Verify build**

Run: `go build ./...`
Expected: Clean build.

**Step 3: Visual check with dev mode**

If dev mode is available, verify:
- Tabs switch correctly
- Users table renders
- "View tokens" switches to Tokens tab with filter
- Token table renders with badges
- Status filter works
- "New Agent Token" opens 5-step stepper
- Agent token creation works end-to-end
- Revoke works

**Step 4: Commit**

```bash
git add internal/web/templates/admin.html
git commit -m "feat(ui): redesign admin dashboard with tabs, filters, and agent token stepper"
```

---

## Task 11: Final build and visual verification

**Files:** None (verification only).

**Step 1: Full build**

Run: `go build ./...`
Expected: Clean build.

**Step 2: Run any existing tests**

Run: `go test ./...`
Expected: All pass. No web tests exist currently so this just confirms nothing else broke.

**Step 3: Verify all static assets are embedded**

Check that the binary serves all expected static files. The `//go:embed static/*` directive in `handler.go` should pick up:
- `theme.css`
- `theme.js`
- `ghp-stepper.js`
- `ghp-repo-select.js`
- `ghp-permission-select.js`
- `octobear.png`

**Step 4: Commit any final adjustments**

If anything needed touching up during verification:

```bash
git add <files>
git commit -m "fix(ui): polish and adjustments from visual verification"
```

---

## Summary of files changed

| Action | File |
|--------|------|
| Copy | `assets/octobear.png` -> `internal/web/static/octobear.png` |
| Create | `internal/web/static/theme.css` |
| Create | `internal/web/static/theme.js` |
| Create | `internal/web/static/ghp-stepper.js` |
| Modify | `internal/web/static/ghp-repo-select.js` (theme vars) |
| Modify | `internal/web/static/ghp-permission-select.js` (theme vars) |
| Rewrite | `internal/web/templates/login.html` |
| Rewrite | `internal/web/templates/admin-login.html` |
| Rewrite | `internal/web/templates/dashboard.html` |
| Rewrite | `internal/web/templates/admin.html` |

No Go code changes needed — `handler.go` already embeds `static/*` and `templates/*.html`.
