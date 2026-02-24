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

  hideNav() {
    const nav = this.shadowRoot && this.shadowRoot.querySelector('.nav');
    if (nav) nav.style.display = 'none';
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
