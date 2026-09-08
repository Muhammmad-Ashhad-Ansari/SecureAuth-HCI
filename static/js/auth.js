/* ============================================================
   SecureAuth shared interaction layer
   Theme, accessibility, contextual help, OTP guidance,
   recovery helpers, activity filters and registration feedback.
   ============================================================ */

const ICON_SUN = '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>';
const ICON_MOON = '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>';

function showToast(message) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.hidden = true; }, 1800);
}

async function copyText(value) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return true;
    }
    const area = document.createElement('textarea');
    area.value = value;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    return ok;
  } catch (_) {
    return false;
  }
}

/* ================= THEME ================= */
(function () {
  const toggle = document.getElementById('themeToggle');
  const icon = document.getElementById('themeIcon');
  if (!toggle || !icon) return;

  function applyTheme(theme) {
    document.body.dataset.theme = theme;
    localStorage.setItem('secureauth-theme', theme);
    icon.innerHTML = theme === 'dark' ? ICON_SUN : ICON_MOON;
  }

  toggle.addEventListener('click', () => {
    applyTheme(document.body.dataset.theme === 'dark' ? 'light' : 'dark');
  });
  applyTheme(localStorage.getItem('secureauth-theme') || localStorage.getItem('pw-theme') || 'dark');
})();

/* ================= ACCESSIBILITY PREFERENCES ================= */
(function () {
  const panel = document.getElementById('accessibilityPanel');
  const toggle = document.getElementById('accessibilityToggle');
  if (!panel || !toggle) return;

  const prefs = {
    prefLargeText: 'pref-large-text',
    prefHighContrast: 'pref-high-contrast',
    prefReduceMotion: 'pref-reduce-motion',
  };

  function applyPref(inputId, className) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const stored = localStorage.getItem(`secureauth-${inputId}`) === '1';
    input.checked = stored;
    document.documentElement.classList.toggle(className, stored);
    input.addEventListener('change', () => {
      document.documentElement.classList.toggle(className, input.checked);
      localStorage.setItem(`secureauth-${inputId}`, input.checked ? '1' : '0');
    });
  }
  Object.entries(prefs).forEach(([id, cls]) => applyPref(id, cls));

  function setOpen(open) {
    panel.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
  }
  toggle.addEventListener('click', () => setOpen(panel.hidden));
  document.querySelectorAll('[data-close-accessibility]').forEach(btn => btn.addEventListener('click', () => setOpen(false)));
  document.querySelectorAll('[data-open-accessibility]').forEach(btn => btn.addEventListener('click', () => setOpen(true)));
  document.addEventListener('keydown', e => { if (e.key === 'Escape') setOpen(false); });
})();

/* ================= CONTEXTUAL HELP ================= */
(function () {
  const modal = document.getElementById('helpModal');
  const text = document.getElementById('helpModalText');
  const close = document.getElementById('helpModalClose');
  const done = document.getElementById('helpModalDone');
  if (!modal || !text) return;
  let returnFocus = null;

  function closeModal() {
    modal.hidden = true;
    if (returnFocus) returnFocus.focus();
  }
  document.querySelectorAll('[data-help]').forEach(btn => {
    btn.addEventListener('click', () => {
      returnFocus = btn;
      text.textContent = btn.dataset.help || '';
      modal.hidden = false;
      (close || done).focus();
    });
  });
  [close, done].forEach(btn => btn && btn.addEventListener('click', closeModal));
  modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !modal.hidden) closeModal(); });
})();

/* ================= OTP 30-SECOND COUNTDOWN + GUIDANCE ================= */
(function () {
  const ring = document.getElementById('otpRing');
  const label = document.getElementById('otpRingLabel');
  const expiryText = document.getElementById('otpExpiryText');
  const warning = document.getElementById('otpExpiryWarning');
  if (!ring) return;

  const circumference = 2 * Math.PI * 15.5;
  ring.style.strokeDasharray = `${circumference}`;

  function tick() {
    const secondsLeft = 30 - (Math.floor(Date.now() / 1000) % 30);
    const fraction = secondsLeft / 30;
    ring.style.strokeDashoffset = `${circumference * (1 - fraction)}`;
    if (label) label.textContent = secondsLeft;
    if (expiryText) expiryText.textContent = `${secondsLeft} second${secondsLeft === 1 ? '' : 's'} left in the current 30-second code.`;
    const expiring = secondsLeft <= 5;
    ring.style.stroke = expiring ? 'var(--warn)' : 'var(--accent)';
    if (warning) warning.hidden = !expiring;
  }
  tick();
  setInterval(tick, 1000);
})();

/* ================= BACKUP CODE MODE ON OTP SCREEN ================= */
(function () {
  const link = document.getElementById('toggleBackupMode');
  const otpBlock = document.getElementById('otpModeBlock');
  const backupBlock = document.getElementById('backupModeBlock');
  const modeInput = document.getElementById('modeInput');
  const otpField = document.getElementById('otpField');
  const backupField = document.getElementById('backupField');
  if (!link || !modeInput || !otpField || !backupField) return;

  function syncMode() {
    const backup = modeInput.value === 'backup';
    otpBlock.hidden = backup;
    backupBlock.hidden = !backup;
    otpField.disabled = backup;
    backupField.disabled = !backup;
    otpField.required = !backup;
    backupField.required = backup;
    link.textContent = backup ? 'Use your authenticator app instead' : 'Authenticator unavailable? Use a recovery code';
  }
  syncMode();

  link.addEventListener('click', e => {
    e.preventDefault();
    modeInput.value = modeInput.value === 'backup' ? 'totp' : 'backup';
    syncMode();
    (modeInput.value === 'backup' ? backupField : otpField).focus();
  });
})();

/* ================= OTP INPUT NORMALIZATION / AUTO-SUBMIT ================= */
(function () {
  const field = document.getElementById('otpField');
  if (!field) return;
  const form = field.closest('form');
  if (!form) return;
  let submitted = false;

  field.addEventListener('input', () => {
    const digitsOnly = field.value.replace(/\D/g, '').slice(0, 6);
    if (digitsOnly !== field.value) field.value = digitsOnly;
    if (!submitted && digitsOnly.length === 6 && !field.disabled) {
      submitted = true;
      form.requestSubmit ? form.requestSubmit() : form.submit();
    }
  });
})();

/* ================= PASSWORD SHOW/HIDE ================= */
(function () {
  const EYE = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>';
  const EYE_OFF = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19M14.12 14.12a3 3 0 1 1-4.24-4.24"/><path d="M1 1l22 22"/>';
  document.querySelectorAll('.pw-toggle').forEach(btn => {
    const input = document.getElementById(btn.dataset.target);
    const icon = btn.querySelector('.pw-eye-icon');
    if (!input || !icon) return;
    btn.addEventListener('click', () => {
      const showing = input.type === 'password';
      input.type = showing ? 'text' : 'password';
      icon.innerHTML = showing ? EYE_OFF : EYE;
      btn.setAttribute('aria-label', showing ? 'Hide password' : 'Show password');
    });
  });
})();

/* ================= REGISTRATION PASSWORD FEEDBACK ================= */
(function () {
  const input = document.getElementById('password');
  const confirm = document.getElementById('confirm_password');
  const wrap = document.getElementById('regStrengthWrap');
  const bar = document.getElementById('regStrengthBar');
  const label = document.getElementById('regStrengthLabel');
  const labelTop = document.getElementById('regStrengthLabelTop');
  const matchState = document.getElementById('passwordMatchState');
  const requirementWrap = document.getElementById('passwordRequirements');
  if (!input || !wrap) return;

  let debounceTimer = null;
  const rules = {
    length: value => value.length >= 8,
    upper: value => /[A-Z]/.test(value),
    lower: value => /[a-z]/.test(value),
    number: value => /\d/.test(value),
    special: value => /[^A-Za-z0-9]/.test(value),
  };

  function renderRules(value) {
    if (!requirementWrap) return;
    Object.entries(rules).forEach(([name, test]) => {
      const el = requirementWrap.querySelector(`[data-rule="${name}"]`);
      if (el) el.classList.toggle('met', test(value));
    });
  }

  function renderMatch() {
    if (!confirm || !matchState) return;
    if (!confirm.value) {
      matchState.textContent = '';
      matchState.className = 'field-state';
      return;
    }
    const matches = confirm.value === input.value;
    matchState.textContent = matches ? '✓ Passwords match' : 'Passwords do not match';
    matchState.className = `field-state ${matches ? 'ok' : 'bad'}`;
  }

  input.addEventListener('input', () => {
    const value = input.value;
    renderRules(value);
    renderMatch();
    if (!value) {
      wrap.hidden = true;
      if (labelTop) labelTop.textContent = 'Start typing';
      return;
    }
    wrap.hidden = false;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(async () => {
      try {
        const res = await fetch('/check-strength', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: value }),
        });
        const data = await res.json();
        bar.style.width = `${data.score}%`;
        bar.style.background = data.score >= 60 ? 'var(--good)' : data.score >= 35 ? 'var(--warn)' : 'var(--bad)';
        label.textContent = data.label;
        if (labelTop) labelTop.textContent = data.label;
      } catch (_) { /* server validation remains authoritative */ }
    }, 220);
  });
  if (confirm) confirm.addEventListener('input', renderMatch);
})();

/* ================= COPY HELPERS ================= */
(function () {
  document.querySelectorAll('[data-copy-target]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const target = document.getElementById(btn.dataset.copyTarget);
      if (target && await copyText(target.textContent.trim())) showToast('Copied securely');
    });
  });

  const copyAll = document.getElementById('copyAllCodes');
  if (copyAll) {
    copyAll.addEventListener('click', async () => {
      const codes = [...document.querySelectorAll('.backup-code-chip')].map(el => el.textContent.trim()).join('\n');
      if (await copyText(codes)) showToast('All recovery codes copied');
    });
  }

  const printBtn = document.getElementById('printCodes');
  if (printBtn) printBtn.addEventListener('click', () => window.print());
})();

/* ================= ACTIVITY FILTERING ================= */
(function () {
  const buttons = [...document.querySelectorAll('.activity-filter')];
  const items = [...document.querySelectorAll('#activityTimeline .timeline-item')];
  const empty = document.getElementById('activityEmptyFilter');
  if (!buttons.length || !items.length) return;

  buttons.forEach(btn => btn.addEventListener('click', () => {
    buttons.forEach(b => b.classList.toggle('active', b === btn));
    const filter = btn.dataset.filter;
    let visible = 0;
    items.forEach(item => {
      const show = filter === 'all' ||
        filter === item.dataset.status ||
        (filter === 'security' && item.dataset.security === 'yes');
      item.hidden = !show;
      if (show) visible += 1;
    });
    if (empty) empty.hidden = visible !== 0;
  }));
})();

/* ================= DISMISSIBLE SUCCESS BANNER ================= */
(function () {
  document.querySelectorAll('.access-granted-banner .banner-close').forEach(btn => {
    btn.addEventListener('click', () => btn.closest('.access-granted-banner').remove());
  });
})();
