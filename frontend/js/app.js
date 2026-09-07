/**
 * User-facing controller.
 *
 * Wires the DOM to the crypto modules and the API.  Everything to do with keys
 * happens inside filecrypto.js; this file only moves files and messages around.
 */

import { ApiError, api, session } from './api.js';
import {
  CryptoError,
  decryptFile,
  encryptFile,
  formatBytes,
  throughputMbps,
  validateFile,
} from './filecrypto.js';
import {
  $, banner, clearBanner, downloadBlob, el, emptyRow, formatDate, formatDuration,
  passphraseStrength, relativeDate, setProgress, show,
} from './ui.js';

let config = null;
let encryptTarget = null;
let decryptTarget = null;
let busy = false;

// ---------------------------------------------------------------------------
// startup
// ---------------------------------------------------------------------------
/**
 * The Web Crypto API is only exposed in a secure context: HTTPS, or localhost.
 * Served over plain HTTP to anything else, `crypto.subtle` is undefined and
 * every operation in this application fails.  Detect that up front and say so
 * plainly, rather than letting it surface as an unreadable TypeError halfway
 * through an encryption (NF.8).
 */
function secureContextProblem() {
  if (window.isSecureContext && window.crypto?.subtle) return null;
  return (
    'This page is not running in a secure context, so the browser will not '
    + 'provide the cryptography it needs. Open it over HTTPS (or via '
    + 'http://localhost during development). Nothing can be encrypted or '
    + 'decrypted until then.'
  );
}

async function start() {
  const insecure = secureContextProblem();
  if (insecure) {
    document.body.prepend(
      el('div', { class: 'banner banner--error', text: insecure }),
    );
    // Leave the page readable but refuse to offer actions that cannot work.
    document.querySelectorAll('button, input, select').forEach((node) => {
      node.disabled = true;
    });
    return;
  }

  try {
    config = await api.config();
  } catch {
    document.body.prepend(
      el('div', {
        class: 'banner banner--error',
        text: 'Could not load settings from the server. Reload the page to try again.',
      }),
    );
    return;
  }

  applyConfig();
  wireAuth();
  wireTabs();
  wireEncrypt();
  wireDecrypt();
  wireFiles();
  wireHistory();
  wireModal();

  if (session.isAuthenticated) {
    try {
      const user = await api.me();
      session.save(session.token, user);
      enterApp(user);
    } catch {
      session.clear();
      showAuth();
    }
  } else {
    showAuth();
  }
}

function applyConfig() {
  const accept = config.allowed_extensions.map((e) => `.${e}`).join(',');
  $('#enc-file').setAttribute('accept', accept);
  $('#enc-hint').textContent =
    `${config.allowed_extensions.map((e) => e.toUpperCase()).join(', ')} — up to ` +
    `${Math.floor(config.max_upload_bytes / (1024 * 1024))} MB`;
  $('#explain-mem').textContent = String(Math.round(config.argon2_memory_kib / 1024));
  $('#explain-iter').textContent = String(config.argon2_iterations);
  $('#retention-days').textContent = String(config.retention_days);
}

function showAuth() {
  show($('#auth-view'), true);
  show($('#app-view'), false);
  show($('#nav'), false);
}

function enterApp(user) {
  show($('#auth-view'), false);
  show($('#app-view'), true);
  show($('#nav'), true);
  $('#who').textContent = `${user.display_name || user.email}${user.role === 'admin' ? ' · administrator' : ''}`;
  show($('#admin-link'), user.role === 'admin');
  refreshFiles();
  refreshHistory();
}

// ---------------------------------------------------------------------------
// authentication
// ---------------------------------------------------------------------------
function wireAuth() {
  const bannerNode = $('#auth-banner');

  for (const tab of document.querySelectorAll('[data-auth-tab]')) {
    tab.addEventListener('click', () => {
      const name = tab.dataset.authTab;
      for (const other of document.querySelectorAll('[data-auth-tab]')) {
        const active = other === tab;
        other.classList.toggle('is-active', active);
        other.setAttribute('aria-selected', String(active));
      }
      for (const panel of document.querySelectorAll('[data-auth-panel]')) {
        panel.hidden = panel.dataset.authPanel !== name;
      }
      clearBanner(bannerNode);
    });
  }

  $('#login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const button = event.target.querySelector('button[type=submit]');
    button.disabled = true;
    try {
      const result = await api.login(form.get('email'), form.get('password'));
      session.save(result.access_token, result.user);
      clearBanner(bannerNode);
      enterApp(result.user);
    } catch (error) {
      banner(bannerNode, 'error', error.message);
    } finally {
      button.disabled = false;
    }
  });

  $('#register-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const button = event.target.querySelector('button[type=submit]');
    button.disabled = true;
    try {
      const result = await api.register(
        form.get('email'), form.get('password'), form.get('display_name') || '',
      );
      session.save(result.access_token, result.user);
      clearBanner(bannerNode);
      enterApp(result.user);
    } catch (error) {
      banner(bannerNode, 'error', error.message);
    } finally {
      button.disabled = false;
    }
  });

  $('#logout').addEventListener('click', () => {
    session.clear();
    location.reload();
  });
}

function wireTabs() {
  for (const tab of document.querySelectorAll('[data-tab]')) {
    tab.addEventListener('click', () => {
      const name = tab.dataset.tab;
      for (const other of document.querySelectorAll('[data-tab]')) {
        const active = other === tab;
        other.classList.toggle('is-active', active);
        other.setAttribute('aria-selected', String(active));
      }
      for (const panel of document.querySelectorAll('[data-panel]')) {
        panel.hidden = panel.dataset.panel !== name;
      }
      if (name === 'files') refreshFiles();
      if (name === 'history') refreshHistory();
    });
  }
}

// ---------------------------------------------------------------------------
// file pickers
// ---------------------------------------------------------------------------
function wireDropzone(zoneId, inputId, onFile) {
  const zone = $(`#${zoneId}`);
  const input = $(`#${inputId}`);

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      input.click();
    }
  });
  input.addEventListener('change', () => {
    if (input.files && input.files[0]) onFile(input.files[0]);
  });

  for (const type of ['dragenter', 'dragover']) {
    zone.addEventListener(type, (event) => {
      event.preventDefault();
      zone.classList.add('is-dragging');
    });
  }
  for (const type of ['dragleave', 'drop']) {
    zone.addEventListener(type, (event) => {
      event.preventDefault();
      zone.classList.remove('is-dragging');
    });
  }
  zone.addEventListener('drop', (event) => {
    const file = event.dataTransfer && event.dataTransfer.files[0];
    if (file) onFile(file);
  });
}

// ---------------------------------------------------------------------------
// encryption
// ---------------------------------------------------------------------------
function wireEncrypt() {
  const info = $('#enc-file-info');
  const bannerNode = $('#enc-banner');
  const passInput = $('#enc-pass');
  const strength = $('#enc-strength');

  wireDropzone('enc-drop', 'enc-file', (file) => {
    clearBanner(bannerNode);
    show($('#enc-result'), false);
    const check = validateFile(file, config);
    info.hidden = false;
    info.className = check.ok ? 'file-info' : 'file-info file-info--error';
    info.textContent = check.ok ? `✓ ${check.message}` : `✗ ${check.message}`;
    encryptTarget = check.ok ? file : null;
  });

  passInput.addEventListener('input', () => {
    const value = passInput.value;
    strength.hidden = value.length === 0;
    const result = passphraseStrength(value);
    strength.className = `strength is-${result.tone}`;
    strength.querySelector('.strength__fill').style.width = `${(result.score / 6) * 100}%`;
    strength.querySelector('.strength__label').textContent = result.label;
  });

  $('#enc-reveal').addEventListener('click', () => togglePassword(passInput, $('#enc-reveal')));
  $('#dec-reveal').addEventListener('click', () => togglePassword($('#dec-pass'), $('#dec-reveal')));

  $('#enc-generate').addEventListener('click', () => {
    const generated = generatePassphrase();
    passInput.value = generated;
    $('#enc-pass2').value = generated;
    passInput.dispatchEvent(new Event('input'));
    // F.4 / 3.2.1: a generated key is shown once with an explicit warning.
    $('#enc-generated-value').textContent = generated;
    show($('#enc-generated'), true);
  });

  $('#enc-copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('#enc-generated-value').textContent);
      $('#enc-copy').textContent = 'Copied';
      setTimeout(() => { $('#enc-copy').textContent = 'Copy'; }, 2000);
    } catch {
      banner(bannerNode, 'warning', 'Could not copy automatically. Select the passphrase and copy it by hand.');
    }
  });

  $('#enc-run').addEventListener('click', runEncrypt);
}

async function runEncrypt() {
  if (busy) return;
  const bannerNode = $('#enc-banner');
  const passphrase = $('#enc-pass').value;
  const confirmation = $('#enc-pass2').value;

  clearBanner(bannerNode);
  show($('#enc-result'), false);

  if (!encryptTarget) {
    banner(bannerNode, 'error', 'Choose a file to encrypt first.');
    return;
  }
  if (passphrase.length < 8) {
    banner(bannerNode, 'error', 'Use a passphrase of at least 8 characters. Longer is better.');
    return;
  }
  if (passphrase !== confirmation) {
    banner(bannerNode, 'error', 'The two passphrases do not match.');
    return;
  }

  const button = $('#enc-run');
  const progress = $('#enc-progress');
  const stage = $('#enc-stage');
  setBusy(true, button, 'Encrypting…');
  show(progress, true);
  show(stage, true);
  setProgress(progress, 0, 'Starting');
  const startedAt = performance.now();

  let outcome;
  try {
    outcome = await encryptFile(encryptTarget, passphrase, config, {
      onStage: (text) => { stage.textContent = text; },
      onProgress: (fraction) => setProgress(progress, fraction, stage.textContent),
    });

    let container = null;
    if ($('#enc-upload').checked) {
      stage.textContent = 'Uploading the sealed container';
      setProgress(progress, 1, 'Uploading');
      container = await api.uploadContainer(outcome.blob, outcome.filename, {
        algorithm: outcome.header.algorithm,
        kdf: outcome.header.kdf,
        segment_count: outcome.header.segment_count,
        plaintext_size: outcome.header.plaintext_size,
      });
    }

    await reportOperation('encrypt', 'success', outcome, encryptTarget, container);
    renderResult($('#enc-result'), {
      title: 'Encrypted',
      lede: container
        ? 'The sealed container has been uploaded to your account and is ready to download.'
        : 'The sealed container is ready to download. It was not uploaded.',
      outcome,
      downloadLabel: 'Download the .enc container',
      extra: [
        ['Algorithm', outcome.header.algorithm],
        ['Key derivation', `${outcome.header.kdf}, ${Math.round(config.argon2_memory_kib / 1024)} MiB × ${config.argon2_iterations}`],
        ['Segments', String(outcome.header.segment_count)],
      ],
      digestLabel: 'SHA-256 of the original file (stored in the container header)',
    });
    banner(bannerNode, 'success', 'Encryption finished and the integrity digest was recorded.');
    // The passphrase is no longer needed; drop it from the form.
    $('#enc-pass').value = '';
    $('#enc-pass2').value = '';
    $('#enc-strength').hidden = true;
    refreshFiles();
    refreshHistory();
  } catch (error) {
    await reportOperation('encrypt', 'failure', outcome, encryptTarget, null, errorCode(error), {
      duration_ms: performance.now() - startedAt,
    });
    banner(bannerNode, 'error', friendlyMessage(error));
  } finally {
    setBusy(false, button, 'Encrypt file');
    show(progress, false);
    show(stage, false);
  }
}

// ---------------------------------------------------------------------------
// decryption
// ---------------------------------------------------------------------------
function wireDecrypt() {
  const info = $('#dec-file-info');
  wireDropzone('dec-drop', 'dec-file', (file) => {
    clearBanner($('#dec-banner'));
    show($('#dec-result'), false);
    decryptTarget = file;
    info.hidden = false;
    info.className = 'file-info';
    info.textContent = `✓ ${file.name} — ${formatBytes(file.size)}`;
  });
  $('#dec-run').addEventListener('click', runDecrypt);
}

async function runDecrypt() {
  if (busy) return;
  const bannerNode = $('#dec-banner');
  clearBanner(bannerNode);
  show($('#dec-result'), false);

  if (!decryptTarget) {
    banner(bannerNode, 'error', 'Choose a .enc container to decrypt first.');
    return;
  }
  const passphrase = $('#dec-pass').value;
  if (!passphrase) {
    banner(bannerNode, 'error', 'Enter the passphrase this container was created with.');
    return;
  }

  const button = $('#dec-run');
  const progress = $('#dec-progress');
  const stage = $('#dec-stage');
  setBusy(true, button, 'Decrypting…');
  show(progress, true);
  show(stage, true);
  setProgress(progress, 0, 'Starting');
  const startedAt = performance.now();

  try {
    const outcome = await decryptFile(decryptTarget, passphrase, config, {
      onStage: (text) => { stage.textContent = text; },
      onProgress: (fraction) => setProgress(progress, fraction, stage.textContent),
    });

    await reportOperation('decrypt', 'success', outcome, decryptTarget, null);
    renderResult($('#dec-result'), {
      title: 'Decrypted and verified',
      lede: 'Every segment authenticated and the SHA-256 digest matches the original file exactly.',
      outcome,
      downloadLabel: `Download ${outcome.filename}`,
      extra: [
        ['Algorithm', outcome.header.algorithm],
        ['Key derivation', outcome.header.kdf],
        ['Segments verified', String(outcome.header.segment_count)],
      ],
      digestLabel: 'SHA-256 of the recovered file (matches the header)',
    });
    banner(bannerNode, 'success', 'Integrity check passed — the file came back byte for byte.');
    $('#dec-pass').value = '';
    refreshHistory();
  } catch (error) {
    await reportOperation('decrypt', 'failure', null, decryptTarget, null, errorCode(error), {
      duration_ms: performance.now() - startedAt,
    });
    banner(bannerNode, 'error', friendlyMessage(error));
    refreshHistory();
  } finally {
    setBusy(false, button, 'Decrypt file');
    show(progress, false);
    show(stage, false);
  }
}

// ---------------------------------------------------------------------------
// stored files
// ---------------------------------------------------------------------------
function wireFiles() {
  $('#files-refresh').addEventListener('click', refreshFiles);
}

async function refreshFiles() {
  const body = $('#files-body');
  if (!body) return;
  try {
    const page = await api.listContainers();
    body.replaceChildren();
    if (page.items.length === 0) {
      body.append(emptyRow(6, 'No encrypted files yet. Encrypt something on the Encrypt tab.'));
      return;
    }
    for (const item of page.items) {
      body.append(
        el('tr', {}, [
          el('td', { text: item.filename }),
          el('td', { text: formatBytes(item.size_bytes) }),
          el('td', {}, [el('span', { class: 'pill pill--accent', text: item.algorithm })]),
          el('td', { text: formatDate(item.created_at) }),
          el('td', {}, [
            item.is_expired
              ? el('span', { class: 'pill pill--error', text: 'expired' })
              : el('span', { class: 'pill pill--muted', text: relativeDate(item.expires_at) }),
          ]),
          el('td', { class: 'right' }, [
            el('div', { class: 'actions' }, [
              el('button', {
                class: 'btn btn--small', text: 'Decrypt',
                onclick: () => openDecryptModal(item),
              }),
              el('button', {
                class: 'btn btn--small', text: 'Download',
                onclick: () => downloadStored(item),
              }),
              el('button', {
                class: 'btn btn--small btn--danger', text: 'Delete',
                onclick: () => removeStored(item),
              }),
            ]),
          ]),
        ]),
      );
    }
  } catch (error) {
    banner($('#files-banner'), 'error', error.message);
  }
}

async function downloadStored(item) {
  try {
    const response = await api.downloadContainer(item.id);
    downloadBlob(await response.blob(), item.filename);
  } catch (error) {
    banner($('#files-banner'), 'error', error.message);
  }
}

async function removeStored(item) {
  if (!confirm(`Delete "${item.filename}"? The stored copy is removed permanently.`)) return;
  try {
    await api.deleteContainer(item.id);
    banner($('#files-banner'), 'success', 'The file and its stored copy have been removed.');
    refreshFiles();
  } catch (error) {
    banner($('#files-banner'), 'error', error.message);
  }
}

// ---------------------------------------------------------------------------
// decrypt-from-storage modal
// ---------------------------------------------------------------------------
let modalItem = null;

function wireModal() {
  $('#modal-cancel').addEventListener('click', closeModal);
  $('#modal-ok').addEventListener('click', runModalDecrypt);
  $('#decrypt-modal').addEventListener('click', (event) => {
    if (event.target === $('#decrypt-modal')) closeModal();
  });
}

function openDecryptModal(item) {
  modalItem = item;
  $('#modal-file').textContent = `${item.filename} — ${formatBytes(item.size_bytes)}`;
  $('#modal-pass').value = '';
  clearBanner($('#modal-banner'));
  show($('#modal-progress'), false);
  show($('#decrypt-modal'), true);
  $('#modal-pass').focus();
}

function closeModal() {
  show($('#decrypt-modal'), false);
  $('#modal-pass').value = '';
  modalItem = null;
}

async function runModalDecrypt() {
  if (!modalItem || busy) return;
  const passphrase = $('#modal-pass').value;
  if (!passphrase) {
    banner($('#modal-banner'), 'error', 'Enter the passphrase for this file.');
    return;
  }

  const button = $('#modal-ok');
  const progress = $('#modal-progress');
  setBusy(true, button, 'Working…');
  show(progress, true);
  setProgress(progress, 0, 'Fetching');
  clearBanner($('#modal-banner'));
  const startedAt = performance.now();
  let file = null;

  try {
    const response = await api.downloadContainer(modalItem.id);
    const blob = await response.blob();
    file = new File([blob], modalItem.filename, { type: 'application/octet-stream' });

    const outcome = await decryptFile(file, passphrase, config, {
      onProgress: (fraction) => setProgress(progress, fraction, 'Decrypting'),
    });

    await reportOperation('decrypt', 'success', outcome, file, modalItem);
    downloadBlob(outcome.blob, outcome.filename);
    closeModal();
    refreshHistory();
  } catch (error) {
    await reportOperation('decrypt', 'failure', null, file, modalItem, errorCode(error), {
      duration_ms: performance.now() - startedAt,
    });
    banner($('#modal-banner'), 'error', friendlyMessage(error));
    refreshHistory();
  } finally {
    setBusy(false, button, 'Decrypt and download');
    show(progress, false);
  }
}

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------
function wireHistory() {
  $('#history-refresh').addEventListener('click', refreshHistory);
}

async function refreshHistory() {
  const body = $('#history-body');
  if (!body) return;
  try {
    const [page, summary] = await Promise.all([api.listOperations(), api.operationSummary()]);

    $('#history-stats').replaceChildren(
      stat('Operations', String(summary.operations_total)),
      stat('Succeeded', String(summary.operations_succeeded)),
      stat('Failed', String(summary.operations_failed)),
      stat('Data processed', formatBytes(summary.bytes_processed)),
      stat('Average time', formatDuration(summary.average_duration_ms)),
    );

    body.replaceChildren();
    if (page.items.length === 0) {
      body.append(emptyRow(8, 'Nothing yet. Your encrypt and decrypt operations will appear here.'));
      return;
    }
    for (const item of page.items) {
      const rate = throughputMbps(item.input_size, item.duration_ms);
      body.append(
        el('tr', {}, [
          el('td', { text: formatDate(item.created_at) }),
          el('td', {}, [
            el('span', {
              class: `pill ${item.kind === 'encrypt' ? 'pill--accent' : 'pill--muted'}`,
              text: item.kind,
            }),
          ]),
          el('td', { text: item.filename || '—' }),
          el('td', { text: formatBytes(item.input_size) }),
          el('td', { text: formatDuration(item.duration_ms) }),
          el('td', { text: rate ? `${rate.toFixed(1)} MB/s` : '—' }),
          el('td', { text: item.peak_memory_bytes ? formatBytes(item.peak_memory_bytes) : '—' }),
          el('td', {}, [
            item.status === 'success'
              ? el('span', { class: 'pill pill--success', text: 'success' })
              : el('span', { class: 'pill pill--error', text: item.error_code || 'failed' }),
          ]),
        ]),
      );
    }
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 401)) {
      body.replaceChildren(emptyRow(8, error.message));
    }
  }
}

function stat(label, value, note) {
  return el('div', { class: 'stat' }, [
    el('div', { class: 'stat__label', text: label }),
    el('div', { class: 'stat__value', text: value }),
    note ? el('div', { class: 'stat__note', text: note }) : null,
  ]);
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------
function renderResult(node, { title, lede, outcome, downloadLabel, extra, digestLabel }) {
  const rate = throughputMbps(outcome.metrics.input_size, outcome.metrics.duration_ms);
  node.replaceChildren(
    el('h3', { text: title }),
    el('p', { class: 'card__lede', text: lede }),
    el('div', { class: 'metrics' }, [
      metric('Time taken', formatDuration(outcome.metrics.duration_ms)),
      metric('Throughput', rate ? `${rate.toFixed(1)} MB/s` : '—'),
      metric('Input', formatBytes(outcome.metrics.input_size)),
      metric('Output', formatBytes(outcome.metrics.output_size)),
      metric(
        'Peak memory',
        formatBytes(outcome.metrics.peak_memory_bytes),
        outcome.metrics.memory_measured ? 'measured' : 'bounded working set',
      ),
    ]),
    el('div', { class: 'metrics' }, extra.map(([label, value]) => metric(label, value))),
    el('p', { class: 'field__label', text: digestLabel }),
    el('p', { class: 'digest', text: outcome.digestHex }),
    el('button', {
      class: 'btn btn--primary',
      text: downloadLabel,
      onclick: () => downloadBlob(outcome.blob, outcome.filename),
    }),
  );
  node.hidden = false;
}

function metric(label, value, note) {
  return el('div', { class: 'metric' }, [
    el('div', { class: 'metric__label', text: label }),
    el('div', { class: 'metric__value', text: value }),
    note ? el('div', { class: 'stat__note', text: note }) : null,
  ]);
}

/** F.10 / F.14: record the operation whether it succeeded or not. */
async function reportOperation(kind, status, outcome, file, container, code, fallback = {}) {
  try {
    await api.recordOperation({
      kind,
      status,
      algorithm: (outcome && outcome.header.algorithm) || 'AES-256-GCM',
      kdf: (outcome && outcome.header.kdf) || 'Argon2id',
      filename: (file && file.name) || (container && container.filename) || '',
      file_type: file ? (file.name.split('.').pop() || '').toLowerCase().slice(0, 32) : '',
      input_size: (outcome && outcome.metrics.input_size) || (file && file.size) || 0,
      output_size: (outcome && outcome.metrics.output_size) || 0,
      duration_ms: (outcome && outcome.metrics.duration_ms)
        || Math.round((fallback.duration_ms || 0) * 100) / 100,
      peak_memory_bytes: (outcome && outcome.metrics.peak_memory_bytes) || 0,
      segment_count: (outcome && outcome.metrics.segment_count) || 0,
      error_code: code || null,
      container_id: (container && container.id) || null,
    });
  } catch {
    // The operation itself already happened locally; a failure to log it must
    // not turn a successful decryption into an error for the user.
  }
}

function errorCode(error) {
  if (error instanceof CryptoError) return error.code;
  if (error instanceof ApiError) return `http_${error.status}`;
  return 'unexpected_error';
}

function friendlyMessage(error) {
  if (error instanceof CryptoError || error instanceof ApiError) return error.message;
  return 'Something went wrong while processing the file. Please try again.';
}

function setBusy(value, button, label) {
  busy = value;
  if (button) {
    button.disabled = value;
    button.textContent = label;
  }
}

function togglePassword(input, button) {
  const revealed = input.type === 'text';
  input.type = revealed ? 'password' : 'text';
  button.textContent = revealed ? 'Show' : 'Hide';
}

/** A diceware-style passphrase: memorable, and still far past guessing range. */
function generatePassphrase() {
  const words = [
    'anchor', 'basalt', 'canyon', 'dahlia', 'ember', 'fathom', 'granite', 'harbour',
    'indigo', 'juniper', 'kestrel', 'lantern', 'marble', 'nectar', 'obsidian', 'pewter',
    'quartz', 'ripple', 'saffron', 'thistle', 'umber', 'velvet', 'willow', 'xenon',
    'yarrow', 'zephyr', 'cobalt', 'driftwood', 'eclipse', 'foxglove', 'glacier', 'hollow',
  ];
  const picks = crypto.getRandomValues(new Uint32Array(5));
  const chosen = Array.from(picks, (n) => words[n % words.length]);
  const digits = crypto.getRandomValues(new Uint32Array(1))[0] % 10000;
  return `${chosen.join('-')}-${String(digits).padStart(4, '0')}`;
}

start();
