/** Small DOM helpers shared by the user and administrator pages. */

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value !== null && value !== undefined) {
      node.setAttribute(key, value);
    }
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function show(node, visible = true) {
  if (node) node.hidden = !visible;
}

/**
 * Render a message into a banner.
 * @param {'info'|'success'|'error'|'warning'} tone
 */
export function banner(node, tone, message) {
  if (!node) return;
  node.className = `banner banner--${tone}`;
  node.textContent = message;
  node.hidden = !message;
  if (tone === 'error') node.setAttribute('role', 'alert');
  else node.setAttribute('role', 'status');
}

export function clearBanner(node) {
  if (node) {
    node.hidden = true;
    node.textContent = '';
  }
}

export function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatDuration(ms) {
  const n = Number(ms) || 0;
  if (n < 1000) return `${n.toFixed(0)} ms`;
  return `${(n / 1000).toFixed(2)} s`;
}

export function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value.endsWith && value.endsWith('Z') ? value : `${value}Z`);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function relativeDate(value) {
  if (!value) return '—';
  const date = new Date(value.endsWith && value.endsWith('Z') ? value : `${value}Z`);
  const diff = date.getTime() - Date.now();
  const days = Math.round(diff / 86400000);
  if (Math.abs(days) >= 1) return `${days > 0 ? 'in' : ''} ${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'}${days < 0 ? ' ago' : ''}`.trim();
  const hours = Math.round(diff / 3600000);
  if (hours === 0) return 'within the hour';
  return `${hours > 0 ? 'in' : ''} ${Math.abs(hours)} hour${Math.abs(hours) === 1 ? '' : 's'}${hours < 0 ? ' ago' : ''}`.trim();
}

/** Hand a Blob to the browser as a download. */
export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  // Give the browser a moment to start the transfer before releasing the URL.
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

export function setProgress(bar, fraction, label) {
  if (!bar) return;
  const pct = Math.max(0, Math.min(100, Math.round(fraction * 100)));
  const fill = bar.querySelector('.progress__fill');
  const text = bar.querySelector('.progress__label');
  if (fill) fill.style.width = `${pct}%`;
  if (text) text.textContent = label ? `${label} — ${pct}%` : `${pct}%`;
  bar.setAttribute('aria-valuenow', String(pct));
}

export function emptyRow(columns, message) {
  return el('tr', {}, [el('td', { colspan: String(columns), class: 'empty', text: message })]);
}

/**
 * Passphrase strength, shown as guidance rather than enforcement — the server
 * never sees this value and cannot check it.
 */
export function passphraseStrength(value) {
  if (!value) return { score: 0, label: 'Enter a passphrase', tone: 'weak' };
  let score = 0;
  if (value.length >= 8) score += 1;
  if (value.length >= 12) score += 1;
  if (value.length >= 20) score += 1;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;

  if (score <= 2) return { score, label: 'Weak — easy to guess', tone: 'weak' };
  if (score <= 4) return { score, label: 'Reasonable', tone: 'fair' };
  return { score, label: 'Strong', tone: 'strong' };
}
