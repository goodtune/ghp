/**
 * <ghp-permission-select> — GitHub-style permissions selector web component.
 *
 * Properties / methods:
 *   .permissions = { contents: "write", pull_requests: "read", ... }
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
    // Repository permissions
    contents:               'Contents',
    pull_requests:          'Pull requests',
    issues:                 'Issues',
    statuses:               'Commit statuses',
    checks:                 'Checks',
    actions:                'Actions',
    workflows:              'Workflows',
    metadata:               'Metadata',
    administration:         'Administration',
    deployments:            'Deployments',
    environments:           'Environments',
    packages:               'Packages',
    pages:                  'Pages',
    security_events:        'Security events',
    vulnerability_alerts:   'Vulnerability alerts',
    discussions:            'Discussions',
    repository_hooks:       'Webhooks',
    secrets:                'Secrets',
    secret_scanning_alerts: 'Secret scanning alerts',
    // Organisation / cross-repo permissions
    members:                'Members',
    projects:               'Projects',
  };

  static descriptions = {
    contents:               'Repository contents, commits, branches, downloads, releases, and merges.',
    pull_requests:          'Pull requests and related comments, assignees, labels, milestones, and merges.',
    issues:                 'Issues and related comments, assignees, labels, and milestones.',
    statuses:               'Commit statuses.',
    checks:                 'Check runs and check suites.',
    actions:                'GitHub Actions workflow runs, jobs, artifacts, caches, and runners.',
    workflows:              'GitHub Actions workflow definitions — enabling, disabling, and dispatching workflows.',
    metadata:               'Search repositories and access basic repository metadata.',
    administration:         'Repository settings, teams, collaborators, and branch protection rules.',
    deployments:            'Deployments and deployment statuses.',
    environments:           'Repository environments and their protection rules.',
    packages:               'GitHub Packages — publish, install, and delete packages.',
    pages:                  'GitHub Pages — read and manage GitHub Pages sites.',
    security_events:        'Code scanning alerts and security advisories.',
    vulnerability_alerts:   'Dependabot vulnerability alerts.',
    discussions:            'Repository discussions and their comments.',
    repository_hooks:       'Repository webhooks.',
    secrets:                'Repository Actions secrets.',
    secret_scanning_alerts: 'Secret scanning alerts.',
    members:                'Organisation members and teams.',
    projects:               'GitHub Projects — repository and organisation project boards.',
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
        rows += `<select data-perm="${this._esc(perm)}" disabled><option value="read">Read</option></select>`;
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
        width: 100%; border: 1px solid #30363d; border-radius: 6px; overflow: hidden;
      }
      .perm-row {
        display: flex; align-items: center; justify-content: space-between;
        padding: 0.625rem 0.75rem; border-bottom: 1px solid #21262d;
      }
      .perm-row:last-child { border-bottom: none; }
      .perm-info { flex: 1; }
      .perm-name {
        font-size: 0.875rem; color: #f0f6fc; font-weight: 500;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }
      .perm-desc {
        font-size: 0.75rem; color: #8b949e; margin-top: 0.125rem;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }
      .perm-control { flex-shrink: 0; margin-left: 1rem; }
      .perm-control select {
        padding: 0.3rem 1.75rem 0.3rem 0.5rem; background: #0d1117;
        border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9;
        font-size: 0.8rem; font-family: inherit;
        appearance: none;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%238b949e' d='M6 8.825a.5.5 0 0 1-.354-.146l-3.5-3.5a.5.5 0 1 1 .708-.708L6 7.618l3.146-3.147a.5.5 0 1 1 .708.708l-3.5 3.5A.5.5 0 0 1 6 8.825z'/%3E%3C/svg%3E");
        background-repeat: no-repeat; background-position: right 0.4rem center;
        cursor: pointer;
      }
      .perm-control select:focus { outline: none; border-color: #58a6ff; }
      .perm-control select:disabled { opacity: 0.6; cursor: default; }
      .perm-empty {
        padding: 1rem; text-align: center; color: #484f58; font-size: 0.875rem;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
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
