import './style.css'
import {
  callProtectedResource,
  createStore,
  defaultRedirectUri,
  escapeHtml,
  randomHex,
  renderLogPanel,
  renderOperationGroup,
  renderStatusItems,
  revokeToken,
} from './shared.js'

const store = createStore('implicit')

const DEFAULT_CONFIG = {
  authorizeEndpoint: import.meta.env.VITE_AUTHORIZE_ENDPOINT ?? 'http://localhost:5001/authorize',
  revocationEndpoint: import.meta.env.VITE_REVOCATION_ENDPOINT ?? 'http://localhost:5001/revoke',
  resourceEndpoint: import.meta.env.VITE_RESOURCE_ENDPOINT ?? 'http://localhost:5002/resource',
  clientId: import.meta.env.VITE_CLIENT_ID ?? 'public-client',
  scope: import.meta.env.VITE_SCOPE ?? 'read',
  operation: 'read',
}

const CONFIG_FIELDS = ['authorizeEndpoint', 'revocationEndpoint', 'resourceEndpoint', 'clientId', 'redirectUri', 'scope', 'operation']

function getConfig() {
  return {
    authorizeEndpoint: store.get('authorizeEndpoint') ?? DEFAULT_CONFIG.authorizeEndpoint,
    revocationEndpoint: store.get('revocationEndpoint') ?? DEFAULT_CONFIG.revocationEndpoint,
    resourceEndpoint: store.get('resourceEndpoint') ?? DEFAULT_CONFIG.resourceEndpoint,
    clientId: store.get('clientId') ?? DEFAULT_CONFIG.clientId,
    redirectUri: store.get('redirectUri') ?? defaultRedirectUri(),
    scope: store.get('scope') ?? DEFAULT_CONFIG.scope,
    operation: store.get('operation') ?? DEFAULT_CONFIG.operation,
  }
}

function saveConfig(cfg) {
  CONFIG_FIELDS.forEach((field) => store.set(field, cfg[field]))
}

function readFormConfig(form) {
  const data = new FormData(form)
  return {
    authorizeEndpoint: data.get('authorizeEndpoint')?.trim() || '',
    revocationEndpoint: data.get('revocationEndpoint')?.trim() || '',
    resourceEndpoint: data.get('resourceEndpoint')?.trim() || '',
    clientId: data.get('clientId')?.trim() || '',
    redirectUri: data.get('redirectUri')?.trim() || '',
    scope: data.get('scope')?.trim() || '',
    operation: data.get('operation')?.trim() || DEFAULT_CONFIG.operation,
  }
}

function clearTokens() {
  store.remove('accessToken', 'tokenType', 'expiresIn', 'grantedScope')
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

  const state = randomHex()
  store.set('state', state)

  const url = buildAuthorizeUrl(cfg, state)
  store.appendLog({
    title: 'Redirect to authorization server',
    request: { method: 'GET', url },
  })

  location.href = url
}

// The implicit grant returns its token (and any error raised after consent) in the URL fragment
// per RFC 6749 §4.2.2, but errors the AS raises before showing the consent screen (unknown scope,
// response type not allowed for this client) come back in the query string — so both are checked.
function processRedirectResponse() {
  const hashParams = new URLSearchParams(location.hash.slice(1))
  const queryParams = new URLSearchParams(location.search)
  const params = new URLSearchParams([...queryParams, ...hashParams])

  const hasResponse = params.has('access_token') || params.has('error')
  if (!hasResponse) {
    return
  }

  const returnedUrl = location.href
  const expectedState = store.get('state')
  store.remove('state')
  history.replaceState(null, '', location.pathname)

  const error = params.get('error')
  if (error) {
    store.appendLog({
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
    store.appendLog({
      title: 'Redirect from authorization server — state mismatch',
      response: {
        method: 'GET',
        url: returnedUrl,
        body: `expected state: ${expectedState}\nreceived state: ${returnedState}`,
      },
    })
    return 'State mismatch on return from the authorization server — token discarded.'
  }

  store.set('accessToken', params.get('access_token') ?? '')
  store.set('tokenType', params.get('token_type') ?? '')
  if (params.has('expires_in')) {
    store.set('expiresIn', params.get('expires_in'))
  }
  if (params.has('scope')) {
    store.set('grantedScope', params.get('scope'))
  }

  store.appendLog({
    title: 'Redirect from authorization server',
    response: { method: 'GET', url: returnedUrl },
  })
}

function render(error) {
  const cfg = getConfig()

  document.querySelector('#app').innerHTML = `
    <header class="app-header">
      <a href="/" class="back-link">&larr; Home</a>
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
            <label>
              Revocation endpoint
              <input type="text" name="revocationEndpoint" value="${escapeHtml(cfg.revocationEndpoint)}" />
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
            <button type="button" id="revoke-token-btn" class="oauth-action-btn">
              <span class="oauth-action-title">Revoke Access Token</span>
              <span class="oauth-action-desc">POST the access token to the revocation endpoint</span>
            </button>
            <button type="button" id="reset-btn" class="oauth-action-btn secondary">
              <span class="oauth-action-title">Reset Session</span>
              <span class="oauth-action-desc">Clear access token and state</span>
            </button>
          </div>

          ${renderOperationGroup(cfg.operation)}
          <div class="oauth-actions-grid">
            <button type="button" id="call-resource-btn" class="oauth-action-btn">
              <span class="oauth-action-title">Call Protected Resource</span>
              <span class="oauth-action-desc">Call the resource endpoint for the selected operation</span>
            </button>
          </div>

          ${error ? `<p class="notice">${escapeHtml(error)}</p>` : ''}

          <h2>Session State</h2>
          <dl class="oauth-status-strip">
            ${renderStatusItems([
              ['Access token', store.get('accessToken')],
              ['Token type', store.get('tokenType')],
              ['Expires in', store.get('expiresIn')],
              ['Scope', store.get('grantedScope')],
            ])}
          </dl>
        </section>
      </form>

      ${renderLogPanel(store.getLogs())}
    </div>
  `

  const form = document.querySelector('#oauth-form')

  document.querySelector('#start-authorization-btn').addEventListener('click', () => {
    startAuthorizationRequest(form)
  })

  document.querySelector('#revoke-token-btn').addEventListener('click', async () => {
    const cfg = readFormConfig(form)
    saveConfig(cfg)
    render(await revokeToken(store, cfg.revocationEndpoint, cfg.clientId, store.get('accessToken'), 'access_token'))
  })

  document.querySelector('#call-resource-btn').addEventListener('click', async () => {
    const cfg = readFormConfig(form)
    saveConfig(cfg)
    await callProtectedResource(store, cfg.resourceEndpoint, cfg.operation, store.get('accessToken'))
    render()
  })

  document.querySelector('#reset-btn').addEventListener('click', () => {
    store.remove('state')
    clearTokens()
    render()
  })

  document.querySelector('#clear-log-btn').addEventListener('click', () => {
    store.clearLogs()
    render()
  })
}

render(processRedirectResponse())
