/**
 * <ghp-repo-select> — searchable repository selector web component.
 *
 * Attributes:
 *   mode="single|multi"  — single-select (default) or multi-select
 *   placeholder="..."    — placeholder text for the search input
 *
 * Properties / methods:
 *   .repos = [...]       — set the available repo list (array of {full_name})
 *   .value               — get selected repos (string in single mode, array in multi)
 *   .clear()             — reset selection and search
 *   .disabled            — get/set disabled state
 *
 * Events:
 *   "change" — fired when selection changes
 */
class GhpRepoSelect extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._repos = [];
    this._selected = [];
    this._open = false;
    this._disabled = false;
  }

  static get observedAttributes() { return ['mode', 'placeholder', 'disabled']; }

  get mode() { return this.getAttribute('mode') || 'single'; }
  get placeholder() { return this.getAttribute('placeholder') || 'Search repositories...'; }

  get disabled() { return this._disabled; }
  set disabled(v) {
    this._disabled = !!v;
    if (this._disabled) this.setAttribute('disabled', '');
    else this.removeAttribute('disabled');
    const input = this.shadowRoot.querySelector('.search-input');
    if (input) input.disabled = this._disabled;
  }

  get repos() { return this._repos; }
  set repos(list) {
    this._repos = (list || []).map(r => typeof r === 'string' ? r : r.full_name);
    this._filterAndRender();
  }

  get value() {
    return this.mode === 'single' ? (this._selected[0] || '') : [...this._selected];
  }
  set value(v) {
    if (this.mode === 'single') {
      this._selected = v ? [v] : [];
    } else {
      this._selected = Array.isArray(v) ? [...v] : [];
    }
    this._renderChips();
    this._filterAndRender();
  }

  clear() {
    this._selected = [];
    const input = this.shadowRoot.querySelector('.search-input');
    if (input) input.value = '';
    this._renderChips();
    this._closeDropdown();
    this.dispatchEvent(new Event('change'));
  }

  connectedCallback() {
    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; }
        * { box-sizing: border-box; }
        .chips { display: flex; flex-wrap: wrap; gap: 0.375rem; margin-bottom: 0.5rem; }
        .chips:empty { display: none; }
        .chip {
          display: inline-flex; align-items: center; gap: 0.25rem;
          background: #21262d; border: 1px solid #30363d; border-radius: 2rem;
          padding: 0.2rem 0.5rem; font-size: 0.8rem; color: #c9d1d9;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        .chip button {
          background: none; border: none; color: #8b949e; cursor: pointer;
          font-size: 0.9rem; padding: 0; line-height: 1; display: flex; align-items: center;
        }
        .chip button:hover { color: #f85149; }
        .wrap { position: relative; }
        .search-input {
          width: 100%; padding: 0.5rem; background: #0d1117;
          border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9;
          font-size: 0.875rem; font-family: inherit;
        }
        .search-input:focus { outline: none; border-color: #58a6ff; box-shadow: 0 0 0 3px rgba(88,166,255,0.3); }
        .search-input:disabled { opacity: 0.5; cursor: not-allowed; }
        .dropdown {
          position: absolute; top: 100%; left: 0; right: 0; z-index: 10;
          background: #161b22; border: 1px solid #30363d; border-top: none;
          border-radius: 0 0 6px 6px; max-height: 200px; overflow-y: auto;
          display: none;
        }
        .dropdown.open { display: block; }
        .option {
          padding: 0.5rem 0.75rem; cursor: pointer; font-size: 0.875rem; color: #c9d1d9;
        }
        .option:hover { background: #21262d; }
        .option.no-results { color: #8b949e; cursor: default; }
        .option.no-results:hover { background: none; }
      </style>
      <div class="chips" id="chips"></div>
      <div class="wrap">
        <input type="text" class="search-input" placeholder="${this._esc(this.placeholder)}" />
        <div class="dropdown" id="dropdown"></div>
      </div>
    `;

    const input = this.shadowRoot.querySelector('.search-input');
    input.disabled = this._disabled;
    input.addEventListener('input', () => this._filterAndRender());
    input.addEventListener('focus', () => this._filterAndRender());

    this._renderChips();
    this._updateInputVisibility();

    // Close dropdown on outside click.
    this._outsideClick = (e) => {
      if (!this.contains(e.target)) this._closeDropdown();
    };
    document.addEventListener('click', this._outsideClick);
  }

  disconnectedCallback() {
    document.removeEventListener('click', this._outsideClick);
  }

  attributeChangedCallback(name) {
    if (name === 'disabled') {
      this._disabled = this.hasAttribute('disabled');
      const input = this.shadowRoot && this.shadowRoot.querySelector('.search-input');
      if (input) input.disabled = this._disabled;
    }
    if (name === 'placeholder') {
      const input = this.shadowRoot && this.shadowRoot.querySelector('.search-input');
      if (input) input.placeholder = this.placeholder;
    }
  }

  _filterAndRender() {
    const input = this.shadowRoot.querySelector('.search-input');
    const dd = this.shadowRoot.querySelector('#dropdown');
    if (!input || !dd) return;

    const q = input.value.toLowerCase();
    const filtered = this._repos.filter(r =>
      !this._selected.includes(r) && r.toLowerCase().includes(q)
    );

    if (filtered.length === 0) {
      if (q) {
        dd.innerHTML = '<div class="option no-results">No matching repositories</div>';
        dd.classList.add('open');
      } else if (this._repos.length === 0) {
        dd.classList.remove('open');
      } else {
        dd.innerHTML = '<div class="option no-results">All repositories selected</div>';
        dd.classList.add('open');
      }
      return;
    }

    dd.innerHTML = '';
    for (const repo of filtered.slice(0, 50)) {
      const opt = document.createElement('div');
      opt.className = 'option';
      opt.textContent = repo;
      opt.addEventListener('click', () => this._selectRepo(repo));
      dd.appendChild(opt);
    }
    dd.classList.add('open');
  }

  _selectRepo(repo) {
    if (this.mode === 'single') {
      this._selected = [repo];
      this.shadowRoot.querySelector('.search-input').value = '';
    } else {
      if (!this._selected.includes(repo)) {
        this._selected.push(repo);
      }
      this.shadowRoot.querySelector('.search-input').value = '';
    }
    this._renderChips();
    this._closeDropdown();
    this.dispatchEvent(new Event('change'));
  }

  _removeRepo(repo) {
    this._selected = this._selected.filter(r => r !== repo);
    this._renderChips();
    this._filterAndRender();
    this.dispatchEvent(new Event('change'));
  }

  _renderChips() {
    const container = this.shadowRoot.querySelector('#chips');
    if (!container) return;
    container.innerHTML = '';
    for (const repo of this._selected) {
      const chip = document.createElement('span');
      chip.className = 'chip';
      const text = document.createTextNode(repo + ' ');
      chip.appendChild(text);
      const btn = document.createElement('button');
      btn.innerHTML = '&times;';
      btn.addEventListener('click', () => this._removeRepo(repo));
      chip.appendChild(btn);
      container.appendChild(chip);
    }
    this._updateInputVisibility();
  }

  _updateInputVisibility() {
    const wrap = this.shadowRoot.querySelector('.wrap');
    if (!wrap) return;
    if (this.mode === 'single' && this._selected.length > 0) {
      wrap.style.display = 'none';
    } else {
      wrap.style.display = '';
    }
  }

  _closeDropdown() {
    const dd = this.shadowRoot.querySelector('#dropdown');
    if (dd) dd.classList.remove('open');
  }

  _esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
}

customElements.define('ghp-repo-select', GhpRepoSelect);
