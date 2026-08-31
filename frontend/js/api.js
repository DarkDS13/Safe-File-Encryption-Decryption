/**
 * REST client.
 *
 * One place that knows how to talk to the server, so error handling and the
 * bearer token live in a single file.  Note what never appears in any request
 * built here: a passphrase or a key.
 */

const TOKEN_KEY = 'sfe.token';
const USER_KEY = 'sfe.user';

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.payload = payload;
  }
}

export const session = {
  get token() {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  get user() {
    try {
      const raw = localStorage.getItem(USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  },
  save(token, user) {
    try {
      localStorage.setItem(TOKEN_KEY, token);
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    } catch {
      /* private browsing: the session simply does not persist */
    }
  },
  clear() {
    try {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
    } catch {
      /* nothing to do */
    }
  },
  get isAuthenticated() {
    return Boolean(this.token);
  },
  get isAdmin() {
    const user = this.user;
    return Boolean(user && user.role === 'admin');
  },
};

async function request(path, { method = 'GET', body, headers = {}, raw = false } = {}) {
  const options = { method, headers: { ...headers } };

  if (body instanceof FormData) {
    options.body = body;
  } else if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }

  const token = session.token;
  if (token) options.headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new ApiError(
      'Could not reach the server. Check your connection and try again.',
      0,
      null,
    );
  }

  if (response.status === 401) {
    session.clear();
    throw new ApiError('Your session has expired. Please sign in again.', 401, null);
  }

  if (!response.ok) {
    let message = `The server returned an error (${response.status}).`;
    let payload = null;
    try {
      payload = await response.json();
      if (payload && payload.error && payload.error.message) message = payload.error.message;
      else if (payload && payload.detail) message = payload.detail;
    } catch {
      /* a non-JSON error body: keep the generic message */
    }
    throw new ApiError(message, response.status, payload);
  }

  if (raw) return response;
  if (response.status === 204) return null;
  return response.json();
}

export const api = {
  config: () => request('/api/config'),
  health: () => request('/api/health'),

  register: (email, password, displayName) =>
    request('/api/auth/register', {
      method: 'POST',
      body: { email, password, display_name: displayName },
    }),
  login: (email, password) =>
    request('/api/auth/login', { method: 'POST', body: { email, password } }),
  me: () => request('/api/auth/me'),

  uploadContainer(blob, filename, meta) {
    const form = new FormData();
    form.append('file', blob, filename);
    form.append('algorithm', meta.algorithm);
    form.append('kdf', meta.kdf);
    form.append('segment_count', String(meta.segment_count));
    form.append('plaintext_size', String(meta.plaintext_size));
    return request('/api/containers', { method: 'POST', body: form });
  },
  listContainers: (limit = 50, offset = 0) =>
    request(`/api/containers?limit=${limit}&offset=${offset}`),
  downloadContainer: (id) => request(`/api/containers/${id}/download`, { raw: true }),
  deleteContainer: (id) => request(`/api/containers/${id}`, { method: 'DELETE' }),

  recordOperation: (payload) => request('/api/operations', { method: 'POST', body: payload }),
  listOperations: (limit = 50, offset = 0) =>
    request(`/api/operations?limit=${limit}&offset=${offset}`),
  operationSummary: () => request('/api/operations/summary'),

  adminUsers: (q = '', limit = 50, offset = 0) =>
    request(`/api/admin/users?limit=${limit}&offset=${offset}${q ? `&q=${encodeURIComponent(q)}` : ''}`),
  adminSuspend: (id) => request(`/api/admin/users/${id}/suspend`, { method: 'POST' }),
  adminReinstate: (id) => request(`/api/admin/users/${id}/reinstate`, { method: 'POST' }),
  adminAudit: (limit = 100, offset = 0, action = '', outcome = '') =>
    request(
      `/api/admin/audit?limit=${limit}&offset=${offset}` +
        `${action ? `&action=${encodeURIComponent(action)}` : ''}` +
        `${outcome ? `&outcome=${outcome}` : ''}`,
    ),
  adminStats: () => request('/api/admin/stats'),
  adminContainers: (limit = 50, offset = 0) =>
    request(`/api/admin/containers?limit=${limit}&offset=${offset}`),
  adminPurge: () => request('/api/admin/purge', { method: 'POST' }),
};
