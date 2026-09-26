// Helpers shared by every flow page (implicit, authorization code + PKCE). Each page passes its
// own storage prefix so the two flows' config, tokens and logs don't overwrite each other.

// Mirrors ProtectedResource's per-scope sub-paths and HTTP verbs (read/GET, write/POST, delete/DELETE).
export const OPERATION_METHODS = {
  read: 'GET',
  write: 'POST',
  delete: 'DELETE',
}

export function defaultRedirectUri() {
  return `${location.origin}${location.pathname}`
}

export function createStore(prefix) {
  const key = (name) => `oauthlab.${prefix}.${name}`
  return {
    get: (name) => sessionStorage.getItem(key(name)),
    set: (name, value) => sessionStorage.setItem(key(name), value),
    remove: (...names) => names.forEach((name) => sessionStorage.removeItem(key(name))),

    getLogs() {
      try {
        return JSON.parse(sessionStorage.getItem(key('logs')) ?? '[]')
      } catch {
        return []
      }
    },
    appendLog(entry) {
      const logs = this.getLogs()
      logs.push({ ...entry, time: new Date().toLocaleTimeString() })
      sessionStorage.setItem(key('logs'), JSON.stringify(logs))
    },
    clearLogs() {
      sessionStorage.removeItem(key('logs'))
    },
  }
}

export function randomHex(byteLength = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength))
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c])
}

export function formatJson(text) {
  if (!text) {
    return text
  }
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}

export async function callProtectedResource(store, resourceEndpoint, operation, accessToken) {
  const op = OPERATION_METHODS[operation] ? operation : 'read'
  const method = OPERATION_METHODS[op]
  const url = `${resourceEndpoint.replace(/\/$/, '')}/${op}`
  const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {}

  try {
    const response = await fetch(url, { method, headers })
    const responseBody = await response.text()

    store.appendLog({
      title: `Call protected resource (${op})`,
      request: { method, url, headers: Object.keys(headers).length ? headers : undefined },
      response: {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: formatJson(responseBody),
      },
    })
  } catch (err) {
    store.appendLog({
      title: `Call protected resource (${op}) — network error`,
      request: { method, url, headers: Object.keys(headers).length ? headers : undefined },
      response: { body: `${err} (likely a CORS or connection issue — is ProtectedResource running?)` },
    })
  }
}

// RFC 7009 token revocation. This client has no secret, so — as at /token — it identifies itself
// with client_id in the body. Returns a message for the page's notice area.
export async function revokeToken(store, revocationEndpoint, clientId, token, tokenTypeHint) {
  if (!token) {
    return `No ${tokenTypeHint.replace('_', ' ')} to revoke.`
  }

  const body = new URLSearchParams({ token, token_type_hint: tokenTypeHint, client_id: clientId })
  const request = {
    method: 'POST',
    url: revocationEndpoint,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  }

  try {
    const response = await fetch(revocationEndpoint, { method: 'POST', headers: request.headers, body })
    const responseBody = await response.text()

    store.appendLog({
      title: 'Revoke access token',
      request,
      response: {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: formatJson(responseBody),
      },
    })

    // The token is deliberately left in storage (a real client would drop it) so the next resource
    // call shows what the revoked token still does.
    return response.ok
      ? 'Access token revoked. It\'s kept here on purpose — call the protected resource with it to see how it\'s treated now.'
      : 'Revocation failed — see the log below.'
  } catch (err) {
    store.appendLog({
      title: 'Revoke access token — network error',
      request,
      response: { body: `${err} (likely a CORS or connection issue — is AuthorizationServer running?)` },
    })
    return 'Revocation failed — see the log below.'
  }
}

export function renderStatusItems(items) {
  return items.map(([label, value]) => `
    <div class="oauth-status-item">
      <dt>${escapeHtml(label)}</dt>
      <dd>${escapeHtml(value ?? '—')}</dd>
    </div>`).join('')
}

export function renderOperationGroup(selected) {
  return `
    <div class="oauth-operation-group">
      <span class="oauth-operation-label">Operation</span>
      ${Object.keys(OPERATION_METHODS).map((op) => `
        <label><input type="radio" name="operation" value="${op}" ${selected === op ? 'checked' : ''} /> ${op[0].toUpperCase()}${op.slice(1)}</label>`).join('')}
    </div>`
}

export function renderLogPanel(logs) {
  return `
    <section class="oauth-panel" id="oauth-console-panel">
      <div class="oauth-console-header">
        <h2>Request / Response Log</h2>
        <button type="button" id="clear-log-btn" class="oauth-action-btn secondary">Clear</button>
      </div>
      <div class="oauth-console-body">
        ${logs.length === 0
          ? '<p class="oauth-console-placeholder">No requests yet.</p>'
          : logs.map(renderLogEntry).join('')}
      </div>
    </section>`
}

function renderLogEntry(entry) {
  const block = (label, b) => {
    if (!b) return ''
    const main = b.method
      ? `${escapeHtml(b.method)} ${escapeHtml(b.url)}`
      : b.status
        ? `${b.status} ${escapeHtml(b.statusText ?? '')}`
        : escapeHtml(b.url ?? '')
    const headersText = b.headers && Object.keys(b.headers).length
      ? Object.entries(b.headers).map(([k, v]) => `${k}: ${v}`).join('\n')
      : ''
    const headers = headersText ? `<pre class="oauth-log-block-headers">${escapeHtml(headersText)}</pre>` : ''
    const body = b.body ? `<pre class="oauth-log-block-body">${escapeHtml(b.body)}</pre>` : ''
    return `
      <div class="oauth-log-block-wrap">
        <span class="oauth-log-block-label">${label}</span>
        <div class="oauth-log-block">
          ${main ? `<p class="oauth-log-block-main">${main}</p>` : ''}
          ${headers}
          ${body}
        </div>
      </div>`
  }

  return `
    <div class="oauth-log-entry">
      <div class="oauth-log-entry-header">
        <span class="oauth-log-title">${escapeHtml(entry.title)}</span>
        <span class="oauth-log-time">${escapeHtml(entry.time)}</span>
      </div>
      ${block('Request', entry.request)}
      ${block('Response', entry.response)}
    </div>`
}
