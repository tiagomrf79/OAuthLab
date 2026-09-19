import './style.css'

const STORAGE_KEYS = {
  authorizeEndpoint: 'oauthlab.config.authorizeEndpoint',
  resourceEndpoint: 'oauthlab.config.resourceEndpoint',
  clientId: 'oauthlab.config.clientId',
  redirectUri: 'oauthlab.config.redirectUri',
  scope: 'oauthlab.config.scope',
  operation: 'oauthlab.config.operation',
  state: 'oauthlab.pendingState',
  accessToken: 'oauthlab.accessToken',
  tokenType: 'oauthlab.tokenType',
  expiresIn: 'oauthlab.expiresIn',
  grantedScope: 'oauthlab.grantedScope',
  logs: 'oauthlab.logs',
}

const DEFAULT_CONFIG = {
  authorizeEndpoint: import.meta.env.VITE_AUTHORIZE_ENDPOINT ?? 'http://localhost:5001/authorize',
  resourceEndpoint: import.meta.env.VITE_RESOURCE_ENDPOINT ?? 'http://localhost:5002/resource',
  clientId: import.meta.env.VITE_CLIENT_ID ?? 'public-client',
  scope: import.meta.env.VITE_SCOPE ?? 'read',
  operation: 'read',
}

// Mirrors ProtectedResource's per-scope sub-paths and HTTP verbs (read/GET, write/POST, delete/DELETE).
const OPERATION_METHODS = {
  read: 'GET',
  write: 'POST',
  delete: 'DELETE',
}

function defaultRedirectUri() {
  return `${location.origin}${location.pathname}`
}

function getConfig() {
  return {
    authorizeEndpoint: sessionStorage.getItem(STORAGE_KEYS.authorizeEndpoint) ?? DEFAULT_CONFIG.authorizeEndpoint,
    resourceEndpoint: sessionStorage.getItem(STORAGE_KEYS.resourceEndpoint) ?? DEFAULT_CONFIG.resourceEndpoint,
    clientId: sessionStorage.getItem(STORAGE_KEYS.clientId) ?? DEFAULT_CONFIG.clientId,
    redirectUri: sessionStorage.getItem(STORAGE_KEYS.redirectUri) ?? defaultRedirectUri(),
    scope: sessionStorage.getItem(STORAGE_KEYS.scope) ?? DEFAULT_CONFIG.scope,
    operation: sessionStorage.getItem(STORAGE_KEYS.operation) ?? DEFAULT_CONFIG.operation,
  }
}

function saveConfig(cfg) {
  sessionStorage.setItem(STORAGE_KEYS.authorizeEndpoint, cfg.authorizeEndpoint)
  sessionStorage.setItem(STORAGE_KEYS.resourceEndpoint, cfg.resourceEndpoint)
  sessionStorage.setItem(STORAGE_KEYS.clientId, cfg.clientId)
  sessionStorage.setItem(STORAGE_KEYS.redirectUri, cfg.redirectUri)
  sessionStorage.setItem(STORAGE_KEYS.scope, cfg.scope)
  sessionStorage.setItem(STORAGE_KEYS.operation, cfg.operation)
}

function readFormConfig(form) {
  const data = new FormData(form)
  return {
    authorizeEndpoint: data.get('authorizeEndpoint')?.trim() || '',
    resourceEndpoint: data.get('resourceEndpoint')?.trim() || '',
    clientId: data.get('clientId')?.trim() || '',
    redirectUri: data.get('redirectUri')?.trim() || '',
    scope: data.get('scope')?.trim() || '',
    operation: data.get('operation')?.trim() || DEFAULT_CONFIG.operation,
  }
}

function getSessionState() {
  return {
    accessToken: sessionStorage.getItem(STORAGE_KEYS.accessToken),
    tokenType: sessionStorage.getItem(STORAGE_KEYS.tokenType),
    expiresIn: sessionStorage.getItem(STORAGE_KEYS.expiresIn),
    grantedScope: sessionStorage.getItem(STORAGE_KEYS.grantedScope),
  }
}

function clearTokens() {
  sessionStorage.removeItem(STORAGE_KEYS.accessToken)
  sessionStorage.removeItem(STORAGE_KEYS.tokenType)
  sessionStorage.removeItem(STORAGE_KEYS.expiresIn)
  sessionStorage.removeItem(STORAGE_KEYS.grantedScope)
}

function generateState() {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function getLogs() {
  try {
    return JSON.parse(sessionStorage.getItem(STORAGE_KEYS.logs) ?? '[]')
  } catch {
    return []
  }
}

function appendLog(entry) {
  const logs = getLogs()
  logs.push({ ...entry, time: new Date().toLocaleTimeString() })
  sessionStorage.setItem(STORAGE_KEYS.logs, JSON.stringify(logs))
}

function clearLogs() {
  sessionStorage.removeItem(STORAGE_KEYS.logs)
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c])
}

function formatJson(text) {
  if (!text) {
    return text
  }
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}

function buildAuthorizeUrl(cfg, state) {
  const url = new URL(cfg.authorizeEndpoint)
  url.searchParams.set('response_type', 'token')
  url.searchParams.set('client_id', cfg.clientId)
  url.searchParams.set('redirect_uri', cfg.redirectUri)
  if (cfg.scope) {
    url.searchParams.set('scope', cfg.scope)
  }
  url.searchParams.set('state', state)
  return url.toString()
}

function startAuthorizationRequest(form) {
  const cfg = readFormConfig(form)
  saveConfig(cfg)

  const state = generateState()
  sessionStorage.setItem(STORAGE_KEYS.state, state)

  const url = buildAuthorizeUrl(cfg, state)
  appendLog({
    title: 'Redirect to authorization server',
    request: { method: 'GET', url },
  })

  location.href = url
}

async function callProtectedResource(form) {
  const cfg = readFormConfig(form)
  saveConfig(cfg)

  const operation = OPERATION_METHODS[cfg.operation] ? cfg.operation : 'read'
  const method = OPERATION_METHODS[operation]
  const url = `${cfg.resourceEndpoint.replace(/\/$/, '')}/${operation}`
  const accessToken = sessionStorage.getItem(STORAGE_KEYS.accessToken)
  const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {}

  try {
    const response = await fetch(url, { method, headers })
    const responseBody = await response.text()

    appendLog({
      title: `Call protected resource (${operation})`,
      request: { method, url, headers: Object.keys(headers).length ? headers : undefined },
      response: {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: formatJson(responseBody),
      },
    })
  } catch (err) {
    appendLog({
      title: `Call protected resource (${operation}) — network error`,
      request: { method, url, headers: Object.keys(headers).length ? headers : undefined },
      response: { body: `${err} (likely a CORS or connection issue — is ProtectedResource running?)` },
    })
  }
}

// The AS returns the token in the URL fragment per the implicit grant (RFC 6749 4.2.2), but
// today it only implements response_type=code and reports "unsupported_response_type" as a
// query parameter instead — so both places are checked until that's added.
function processRedirectResponse() {
  const hashParams = new URLSearchParams(location.hash.slice(1))
  const queryParams = new URLSearchParams(location.search)
  const params = new URLSearchParams([...queryParams, ...hashParams])

  const hasResponse = params.has('access_token') || params.has('error')
  if (!hasResponse) {
    return
  }

  const returnedUrl = location.href
  const expectedState = sessionStorage.getItem(STORAGE_KEYS.state)
  sessionStorage.removeItem(STORAGE_KEYS.state)
  history.replaceState(null, '', location.pathname)

  const error = params.get('error')
  if (error) {
    appendLog({
      title: 'Redirect from authorization server — error',
      response: {
        method: 'GET',
        url: returnedUrl,
        body: `error: ${error}\ndescription: ${params.get('error_description') ?? '(none)'}`,
      },
    })
    return 'Authorization server returned an error — see the log below.'
  }

  const returnedState = params.get('state')
  if (returnedState !== expectedState) {
    appendLog({
      title: 'Redirect from authorization server — state mismatch',
      response: {
        method: 'GET',
        url: returnedUrl,
        body: `expected state: ${expectedState}\nreceived state: ${returnedState}`,
      },
    })
    return 'State mismatch on return from the authorization server — token discarded.'
  }

  sessionStorage.setItem(STORAGE_KEYS.accessToken, params.get('access_token') ?? '')
  sessionStorage.setItem(STORAGE_KEYS.tokenType, params.get('token_type') ?? '')
  if (params.has('expires_in')) {
    sessionStorage.setItem(STORAGE_KEYS.expiresIn, params.get('expires_in'))
  }
  if (params.has('scope')) {
    sessionStorage.setItem(STORAGE_KEYS.grantedScope, params.get('scope'))
  }

  appendLog({
    title: 'Redirect from authorization server',
    response: { method: 'GET', url: returnedUrl },
  })
}

function resetSession() {
  sessionStorage.removeItem(STORAGE_KEYS.state)
  clearTokens()
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

function render(error) {
  const cfg = getConfig()
  const session = getSessionState()
  const logs = getLogs()

  document.querySelector('#app').innerHTML = `
    <header class="app-header">
      <h1>OAuth2 Public Client</h1>
      <p>Implicit Grant flow playground</p>
    </header>

    <div class="oauth-client-layout">
      <form id="oauth-form">
        <section class="oauth-panel" id="oauth-config-panel">
          <h2>Configuration</h2>

          <div class="oauth-field-group">
            <h3>Authorization Server</h3>
            <label>
              Authorize endpoint
              <input type="text" name="authorizeEndpoint" value="${escapeHtml(cfg.authorizeEndpoint)}" />
            </label>
          </div>

          <div class="oauth-field-group">
            <h3>Protected Resource</h3>
            <label>
              Resource endpoint
              <input type="text" name="resourceEndpoint" value="${escapeHtml(cfg.resourceEndpoint)}" />
            </label>
          </div>

          <div class="oauth-field-group">
            <h3>Client</h3>
            <label>
              Client ID
              <input type="text" name="clientId" value="${escapeHtml(cfg.clientId)}" />
            </label>
            <label>
              Redirect URI
              <input type="text" name="redirectUri" value="${escapeHtml(cfg.redirectUri)}" />
            </label>
            <label>
              Scope
              <input type="text" name="scope" value="${escapeHtml(cfg.scope)}" />
            </label>
          </div>
        </section>

        <section class="oauth-panel" id="oauth-actions-panel">
          <h2>Actions</h2>
          <div class="oauth-actions-grid">
            <button type="button" id="start-authorization-btn" class="oauth-action-btn">
              <span class="oauth-action-title">Start Authorization Request</span>
              <span class="oauth-action-desc">Redirect to the authorize endpoint (response_type=token)</span>
            </button>
            <button type="button" id="reset-btn" class="oauth-action-btn secondary">
              <span class="oauth-action-title">Reset Session</span>
              <span class="oauth-action-desc">Clear access token and state</span>
            </button>
          </div>

          <div class="oauth-operation-group">
            <span class="oauth-operation-label">Operation</span>
            <label><input type="radio" name="operation" value="read" ${cfg.operation === 'read' ? 'checked' : ''} /> Read</label>
            <label><input type="radio" name="operation" value="write" ${cfg.operation === 'write' ? 'checked' : ''} /> Write</label>
            <label><input type="radio" name="operation" value="delete" ${cfg.operation === 'delete' ? 'checked' : ''} /> Delete</label>
          </div>
          <div class="oauth-actions-grid">
            <button type="button" id="call-resource-btn" class="oauth-action-btn">
              <span class="oauth-action-title">Call Protected Resource</span>
              <span class="oauth-action-desc">Call the resource endpoint for the selected operation</span>
            </button>
          </div>

          ${error ? `<p class="notice">${escapeHtml(error)}</p>` : ''}

          <h2>Session State</h2>
          <dl class="oauth-status-strip">
            <div class="oauth-status-item">
              <dt>Access token</dt>
              <dd>${escapeHtml(session.accessToken ?? '—')}</dd>
            </div>
            <div class="oauth-status-item">
              <dt>Token type</dt>
              <dd>${escapeHtml(session.tokenType ?? '—')}</dd>
            </div>
            <div class="oauth-status-item">
              <dt>Expires in</dt>
              <dd>${escapeHtml(session.expiresIn ?? '—')}</dd>
            </div>
            <div class="oauth-status-item">
              <dt>Scope</dt>
              <dd>${escapeHtml(session.grantedScope ?? '—')}</dd>
            </div>
          </dl>
        </section>
      </form>

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
      </section>
    </div>
  `

  const form = document.querySelector('#oauth-form')

  document.querySelector('#start-authorization-btn').addEventListener('click', () => {
    startAuthorizationRequest(form)
  })

  document.querySelector('#call-resource-btn').addEventListener('click', async () => {
    await callProtectedResource(form)
    render()
  })

  document.querySelector('#reset-btn').addEventListener('click', () => {
    resetSession()
    render()
  })

  document.querySelector('#clear-log-btn').addEventListener('click', () => {
    clearLogs()
    render()
  })
}

render(processRedirectResponse())
