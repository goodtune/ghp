/**
 * <ghp-permission-select> — GitHub-style permissions selector web component.
 *
 * Properties / methods:
 *   .permissions = { contents: "write", pulls: "read", ... }
 *       Set the available permissions and their max granted level.
 *   .value
 *       Get the selected permissions as { permission: level } (excludes "No access").
 *   .clear()
 *       Reset all permissions to "No access".
 *
 * Events:
 *   "change" — fired when any permission level changes
 */
class GhpPermissionSelect extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._permissions = {};
  }

  // Human-readable labels.
  static labels = {
    contents:           'Contents',
    pulls:              'Pull requests',
    issues:             'Issues',
    statuses:           'Commit statuses',
    checks:             'Checks',
    actions:            'Actions',
    metadata:           'Metadata',
    administration:     'Administration',
    members:            'Members',
    pages:              'Pages',
    security_events:    'Security events',
    vulnerability_alerts: 'Vulnerability alerts',
    workflows:          'Workflows',
    packages:           'Packages',
    environments:       'Environments',
    deployments:        'Deployments',
    discussions:        'Discussions',
    projects:           'Projects',
  };

  static descriptions = {
    contents:  'Repository contents, commits, branches, downloads, releases, and merges.',
    pulls:     'Pull requests and related comments, assignees, labels, milestones, and merges.',
    issues:    'Issues and related comments, assignees, labels, and milestones.',
    statuses:  'Commit statuses.',
    checks:    'Check runs and check suites.',
    actions:   'GitHub Actions workflows, runs, and artifacts.',
    metadata:  'Search repositories, list collaborators, and access repository metadata.',
  };

  get permissions() { return this._permissions; }
  set permissions(perms) {
    this._permissions = perms || {};
    this._render();
  }

  get value() {
    const result = {};
    const selects = this.shadowRoot.querySelectorAll('select[data-perm]');
    for (const sel of selects) {
      if (sel.value) result[sel.dataset.perm] = sel.value;
    }
    return result;
  }

  clear() {
    const selects = this.shadowRoot.querySelectorAll('select[data-perm]');
    for (const sel of selects) sel.value = '';
    this.dispatchEvent(new Event('change'));
  }

  connectedCallback() {
    this._render();
  }

  _render() {
    const keys = Object.keys(this._permissions).sort();

    if (keys.length === 0) {
      this.shadowRoot.innerHTML = `
        <style>${this._styles()}</style>
        <div class="perm-table"><div class="perm-empty">No permissions available</div></div>
      `;
      return;
    }

    let rows = '';
    for (const perm of keys) {
      const granted = this._permissions[perm];
      const label = GhpPermissionSelect.labels[perm] || perm.charAt(0).toUpperCase() + perm.slice(1).replace(/_/g, ' ');
      const desc = GhpPermissionSelect.descriptions[perm] || '';
      const isMetadata = perm === 'metadata';

      rows += `<div class="perm-row">`;
      rows += `  <div class="perm-info">`;
      rows += `    <div class="perm-name">${this._esc(label)}</div>`;
      if (desc) rows += `    <div class="perm-desc">${this._esc(desc)}</div>`;
      rows += `  </div>`;
      rows += `  <div class="perm-control">`;

      if (isMetadata) {
        rows += `<select disabled><option>Read</option></select>`;
      } else {
        rows += `<select data-perm="${this._esc(perm)}">`;
        rows += `  <option value="">No access</option>`;
        rows += `  <option value="read">Read</option>`;
        if (granted === 'write') {
          rows += `  <option value="write">Read and write</option>`;
        }
        rows += `</select>`;
      }

      rows += `  </div>`;
      rows += `</div>`;
    }

    this.shadowRoot.innerHTML = `
      <style>${this._styles()}</style>
      <div class="perm-table">${rows}</div>
    `;

    // Attach change listeners.
    for (const sel of this.shadowRoot.querySelectorAll('select[data-perm]')) {
      sel.addEventListener('change', () => this.dispatchEvent(new Event('change')));
    }
  }

  _styles() {
    return `
      :host { display: block; }
      * { box-sizing: border-box; }
      .perm-table {
        width: 100%; border: 1px solid var(--color-border, #30363d); border-radius: 6px; overflow: hidden;
      }
      .perm-row {
        display: flex; align-items: center; justify-content: space-between;
        padding: 0.625rem 0.75rem; border-bottom: 1px solid var(--color-border-subtle, #21262d);
      }
      .perm-row:last-child { border-bottom: none; }
      .perm-info { flex: 1; }
      .perm-name {
        font-size: 0.875rem; color: var(--color-text-heading, #f0f6fc); font-weight: 500;
        font-family: var(--font-sans, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif);
      }
      .perm-desc {
        font-size: 0.75rem; color: var(--color-text-secondary, #8b949e); margin-top: 0.125rem;
        font-family: var(--font-sans, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif);
      }
      .perm-control { flex-shrink: 0; margin-left: 1rem; }
      .perm-control select {
        padding: 0.3rem 1.75rem 0.3rem 0.5rem; background: var(--color-input-bg, #0d1117);
        border: 1px solid var(--color-border, #30363d); border-radius: 6px; color: var(--color-text, #c9d1d9);
        font-size: 0.8rem; font-family: inherit;
        appearance: none;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%238b949e' d='M6 8.825a.5.5 0 0 1-.354-.146l-3.5-3.5a.5.5 0 1 1 .708-.708L6 7.618l3.146-3.147a.5.5 0 1 1 .708.708l-3.5 3.5A.5.5 0 0 1 6 8.825z'/%3E%3C/svg%3E");
        background-repeat: no-repeat; background-position: right 0.4rem center;
        cursor: pointer;
      }
      .perm-control select:focus { outline: none; border-color: var(--color-focus, #58a6ff); }
      .perm-control select:disabled { opacity: 0.6; cursor: default; }
      .perm-empty {
        padding: 1rem; text-align: center; color: var(--color-text-secondary, #484f58); font-size: 0.875rem;
        font-family: var(--font-sans, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif);
      }
    `;
  }

  _esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
}

customElements.define('ghp-permission-select', GhpPermissionSelect);
