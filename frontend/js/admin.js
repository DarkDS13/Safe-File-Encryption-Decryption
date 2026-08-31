/**
 * Administrator controller (module 0.7).
 *
 * The role check below decides what to draw.  It is not the access control —
 * that is enforced on the server for every request (F.12).
 */

import { api, session } from './api.js';
import {
  $, banner, el, emptyRow, formatBytes, formatDate, formatDuration, relativeDate, show,
} from './ui.js';

async function start() {
  if (!session.isAuthenticated) {
    location.href = '/';
    return;
  }

  let user;
  try {
    user = await api.me();
  } catch {
    session.clear();
    location.href = '/';
    return;
  }

  $('#who').textContent = `${user.display_name || user.email} · ${user.role}`;
  $('#logout').addEventListener('click', () => {
    session.clear();
    location.href = '/';
  });

  if (user.role !== 'admin') {
    show($('#denied'), true);
    return;
  }

  show($('#admin-view'), true);
  wireTabs();
  $('#users-refresh').addEventListener('click', loadUsers);
  $('#audit-refresh').addEventListener('click', loadAudit);
  $('#audit-outcome').addEventListener('change', loadAudit);
  $('#containers-refresh').addEventListener('click', loadContainers);
  $('#purge-run').addEventListener('click', runPurge);

  let searchTimer = null;
  $('#user-search').addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(loadUsers, 250);
  });

  await Promise.all([loadStats(), loadUsers()]);
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
      if (name === 'users') loadUsers();
      if (name === 'audit') loadAudit();
      if (name === 'containers') loadContainers();
    });
  }
}

// ---------------------------------------------------------------------------
// statistics
// ---------------------------------------------------------------------------
async function loadStats() {
  try {
    const stats = await api.adminStats();
    $('#stat-cards').replaceChildren(
      stat('Accounts', String(stats.users_total), `${stats.users_suspended} suspended`),
      stat('Stored containers', String(stats.containers_total), `${stats.containers_expired} past retention`),
      stat('Storage used', formatBytes(stats.stored_bytes)),
      stat('Operations', String(stats.operations_total), `${stats.operations_failed} failed`),
      stat('Last 24 hours', String(stats.operations_last_24h)),
      stat('Average time', formatDuration(stats.average_duration_ms)),
      stat('Throughput', `${stats.average_throughput_mbps} MB/s`, 'across all operations'),
      stat('Encrypted', formatBytes(stats.bytes_encrypted), `${formatBytes(stats.bytes_decrypted)} decrypted`),
    );
  } catch (error) {
    banner($('#admin-banner'), 'error', error.message);
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
// accounts
// ---------------------------------------------------------------------------
async function loadUsers() {
  const body = $('#users-body');
  try {
    const page = await api.adminUsers($('#user-search').value.trim());
    body.replaceChildren();
    if (page.items.length === 0) {
      body.append(emptyRow(7, 'No accounts match that filter.'));
      return;
    }

    const self = session.user;
    for (const item of page.items) {
      const isSelf = self && item.id === self.id;
      body.append(
        el('tr', {}, [
          el('td', { text: item.email }),
          el('td', { text: item.display_name || '—' }),
          el('td', {}, [
            el('span', {
              class: `pill ${item.role === 'admin' ? 'pill--accent' : 'pill--muted'}`,
              text: item.role,
            }),
          ]),
          el('td', {}, [
            item.is_suspended
              ? el('span', { class: 'pill pill--error', text: 'suspended' })
              : el('span', { class: 'pill pill--success', text: 'active' }),
          ]),
          el('td', { text: formatDate(item.created_at) }),
          el('td', { text: item.last_login_at ? formatDate(item.last_login_at) : 'never' }),
          el('td', { class: 'right' }, [
            el('div', { class: 'actions' }, [
              isSelf
                ? el('span', { class: 'stat__note', text: 'this is you' })
                : el('button', {
                    class: `btn btn--small ${item.is_suspended ? '' : 'btn--danger'}`,
                    text: item.is_suspended ? 'Reinstate' : 'Suspend',
                    onclick: () => toggleSuspend(item),
                  }),
            ]),
          ]),
        ]),
      );
    }
  } catch (error) {
    body.replaceChildren(emptyRow(7, error.message));
  }
}

async function toggleSuspend(item) {
  const action = item.is_suspended ? 'reinstate' : 'suspend';
  if (!confirm(`${action === 'suspend' ? 'Suspend' : 'Reinstate'} ${item.email}?`)) return;
  try {
    if (item.is_suspended) await api.adminReinstate(item.id);
    else await api.adminSuspend(item.id);
    banner($('#admin-banner'), 'success', `${item.email} has been ${action}d.`);
    await Promise.all([loadUsers(), loadStats()]);
  } catch (error) {
    banner($('#admin-banner'), 'error', error.message);
  }
}

// ---------------------------------------------------------------------------
// audit log
// ---------------------------------------------------------------------------
async function loadAudit() {
  const body = $('#audit-body');
  try {
    const page = await api.adminAudit(150, 0, '', $('#audit-outcome').value);
    body.replaceChildren();
    if (page.items.length === 0) {
      body.append(emptyRow(6, 'No log entries match that filter.'));
      return;
    }
    for (const item of page.items) {
      body.append(
        el('tr', {}, [
          el('td', { text: formatDate(item.created_at) }),
          el('td', { text: item.actor_email }),
          el('td', {}, [el('span', { class: 'pill pill--muted', text: item.action })]),
          el('td', {}, [
            el('span', {
              class: `pill ${item.outcome === 'success' ? 'pill--success' : 'pill--error'}`,
              text: item.outcome,
            }),
          ]),
          el('td', { class: 'mono', text: item.detail || '—' }),
          el('td', { class: 'mono', text: item.ip_address || '—' }),
        ]),
      );
    }
  } catch (error) {
    body.replaceChildren(emptyRow(6, error.message));
  }
}

// ---------------------------------------------------------------------------
// stored containers
// ---------------------------------------------------------------------------
async function loadContainers() {
  const body = $('#containers-body');
  try {
    const page = await api.adminContainers();
    body.replaceChildren();
    if (page.items.length === 0) {
      body.append(emptyRow(6, 'No containers are stored.'));
      return;
    }
    for (const item of page.items) {
      body.append(
        el('tr', {}, [
          el('td', { text: item.filename }),
          el('td', { text: item.owner_email }),
          el('td', { text: formatBytes(item.size_bytes) }),
          el('td', {}, [el('span', { class: 'pill pill--accent', text: item.algorithm })]),
          el('td', { text: formatDate(item.created_at) }),
          el('td', {}, [
            item.is_expired
              ? el('span', { class: 'pill pill--error', text: 'expired' })
              : el('span', { class: 'pill pill--muted', text: relativeDate(item.expires_at) }),
          ]),
        ]),
      );
    }
  } catch (error) {
    body.replaceChildren(emptyRow(6, error.message));
  }
}

// ---------------------------------------------------------------------------
// maintenance
// ---------------------------------------------------------------------------
async function runPurge() {
  if (!confirm('Permanently remove every container whose retention period has passed?')) return;
  const button = $('#purge-run');
  button.disabled = true;
  try {
    const result = await api.adminPurge();
    const node = $('#purge-result');
    node.className = 'callout';
    node.textContent =
      result.purged === 0
        ? 'Nothing to purge — no container has passed its retention period.'
        : `Purged ${result.purged} container${result.purged === 1 ? '' : 's'}, freeing ${formatBytes(result.freed_bytes)}.`;
    node.hidden = false;
    await Promise.all([loadStats(), loadContainers()]);
  } catch (error) {
    banner($('#admin-banner'), 'error', error.message);
  } finally {
    button.disabled = false;
  }
}

start();
