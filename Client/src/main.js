import './style.css'
import {
  randomString,
  getSession,
  setSession,
  clearSession,
  buildAuthorizeUrl,
  exchangeCodeForToken,
  refreshAccessToken,
  callProtectedResource,
} from './oauth.js'
import { appendLog, clearLog, renderStoredLog } from './log.js'

document.querySelector('#app').innerHTML = `
  <header class="app-header">
    <h1>OAuth2 Test Client</h1>
    <p class="subtitle">Authorization Code flow playground &mdash; <em>OAuth 2 in Action</em></p>
  </header>

  <main class="layout">
    <section class="panel" id="config-panel">
      <h2>Configuration</h2>

      <div class="field-group">
        <h3>Authorization Server</h3>
        <label>
          Authorize endpoint
          <input type="text" id="cfg-authorize-endpoint" value="${import.meta.env.VITE_AUTHORIZE_ENDPOINT}" />
        </label>
        <label>
          Token endpoint
          <input type="text" id="cfg-token-endpoint" value="${import.meta.env.VITE_TOKEN_ENDPOINT}" />
        </label>
      </div>

      <div class="field-group">
        <h3>Protected Resource</h3>
        <label>
          Resource endpoint
          <input type="text" id="cfg-resource-endpoint" value="${import.meta.env.VITE_RESOURCE_ENDPOINT}" />
        </label>
      </div>

      <div class="field-group">
        <h3>Client</h3>
        <label>
          Client ID
          <input type="text" id="cfg-client-id" value="${import.meta.env.VITE_CLIENT_ID}" />
        </label>
        <label>
          Client secret
          <input type="password" id="cfg-client-secret" value="${import.meta.env.VITE_CLIENT_SECRET}" />
        </label>
        <label>
          Redirect URI
          <input type="text" id="cfg-redirect-uri" value="${import.meta.env.VITE_REDIRECT_URI}" />
        </label>
        <label>
          Scope
          <input type="text" id="cfg-scope" value="${import.meta.env.VITE_SCOPE}" />
        </label>
      </div>
    </section>

    <section class="panel" id="actions-panel">
      <h2>Actions</h2>
      <div class="actions-grid">
        <button type="button" class="action-btn" id="btn-authorize">
          <span class="action-title">Start Authorization Request</span>
          <span class="action-desc">Redirect to the authorize endpoint</span>
        </button>
        <button type="button" class="action-btn" id="btn-exchange-token">
          <span class="action-title">Exchange Code for Tokens</span>
          <span class="action-desc">POST the authorization code to the token endpoint</span>
        </button>
        <button type="button" class="action-btn" id="btn-refresh-token">
          <span class="action-title">Refresh Access Token</span>
          <span class="action-desc">POST the refresh token to the token endpoint</span>
        </button>
        <button type="button" class="action-btn" id="btn-call-resource">
          <span class="action-title">Call Protected Resource</span>
          <span class="action-desc">GET the resource with the access token</span>
        </button>
        <button type="button" class="action-btn secondary" id="btn-reset">
          <span class="action-title">Reset Session</span>
          <span class="action-desc">Clear code, tokens and state</span>
        </button>
      </div>

      <p class="notice" id="notice" hidden></p>

      <h2>Session State</h2>
      <dl class="status-strip">
        <div class="status-item">
          <dt>State</dt>
          <dd id="status-state">&mdash;</dd>
        </div>
        <div class="status-item">
          <dt>Authorization code</dt>
          <dd id="status-code">&mdash;</dd>
        </div>
        <div class="status-item">
          <dt>Access token</dt>
          <dd id="status-access-token">&mdash;</dd>
        </div>
        <div class="status-item">
          <dt>Token type</dt>
          <dd id="status-token-type">&mdash;</dd>
        </div>
        <div class="status-item">
          <dt>Expires in</dt>
          <dd id="status-expires-in">&mdash;</dd>
        </div>
        <div class="status-item">
          <dt>Refresh token</dt>
          <dd id="status-refresh-token">&mdash;</dd>
        </div>
      </dl>
    </section>

    <section class="panel" id="console-panel">
      <div class="console-header">
        <h2>Request / Response Log</h2>
        <button type="button" class="action-btn secondary" id="btn-clear-console">Clear</button>
      </div>
      <div class="console-body" id="console-body">
        <p class="console-placeholder">No requests yet.</p>
      </div>
    </section>
  </main>
`

function readConfig() {
  return {
    authorizeEndpoint: document.getElementById('cfg-authorize-endpoint').value.trim(),
    tokenEndpoint: document.getElementById('cfg-token-endpoint').value.trim(),
    resourceEndpoint: document.getElementById('cfg-resource-endpoint').value.trim(),
    clientId: document.getElementById('cfg-client-id').value.trim(),
    clientSecret: document.getElementById('cfg-client-secret').value,
    redirectUri: document.getElementById('cfg-redirect-uri').value.trim(),
    scope: document.getElementById('cfg-scope').value.trim(),
  }
}

function hideNotice() {
  const notice = document.getElementById('notice')
  notice.hidden = true
  notice.textContent = ''
}

function showNotice(text) {
  const notice = document.getElementById('notice')
  notice.textContent = text
  notice.hidden = false
}

function refreshStatusStrip() {
  document.getElementById('status-state').textContent = getSession('state') || '—'
  document.getElementById('status-code').textContent = getSession('code') || '—'
  document.getElementById('status-access-token').textContent = getSession('access_token') || '—'
  document.getElementById('status-token-type').textContent = getSession('token_type') || '—'
  document.getElementById('status-expires-in').textContent = getSession('expires_in') || '—'
  document.getElementById('status-refresh-token').textContent = getSession('refresh_token') || '—'
}

function processRedirectResponse() {
  const params = new URLSearchParams(window.location.search)
  if (!params.has('code') && !params.has('error')) return

  const response = { method: 'GET', url: window.location.href, headers: { Referer: document.referrer } }

  if (params.has('error')) {
    response.body = `error: ${params.get('error')}\ndescription: ${params.get('error_description') || '(none)'}`
    appendLog({ title: 'Redirect from authorization server — error', response })
    history.replaceState({}, '', window.location.pathname)
    return
  }

  const returnedState = params.get('state')
  const expectedState = getSession('state')
  if (returnedState !== expectedState) {
    response.body = `expected state: ${expectedState}\nreceived state: ${returnedState}`
    appendLog({ title: 'Redirect from authorization server — state mismatch', response })
    history.replaceState({}, '', window.location.pathname)
    return
  }

  const code = params.get('code')
  setSession('code', code)
  appendLog({ title: 'Redirect from authorization server', response })
  history.replaceState({}, '', window.location.pathname)
  refreshStatusStrip()
}

document.getElementById('btn-authorize').addEventListener('click', () => {
  hideNotice()
  const config = readConfig()
  const state = randomString()
  setSession('state', state)
  setSession('code', '')
  const url = buildAuthorizeUrl(config, state)
  appendLog({ title: 'Redirect to authorization server', request: { method: 'GET', url } })
  window.location.replace(url)
})

document.getElementById('btn-exchange-token').addEventListener('click', async () => {
  hideNotice()
  const config = readConfig()
  const code = getSession('code')
  if (!code) {
    showNotice('No authorization code in session — run "Start Authorization Request" first.')
    return
  }

  const { request, response, json } = await exchangeCodeForToken(config, code)
  appendLog({ title: 'Exchange code for tokens', request, response })

  if (json) {
    setSession('access_token', json.access_token)
    setSession('token_type', json.token_type)
    setSession('expires_in', json.expires_in?.toString())
    setSession('refresh_token', json.refresh_token)
    refreshStatusStrip()
  }
})

document.getElementById('btn-refresh-token').addEventListener('click', async () => {
  hideNotice()
  const config = readConfig()
  const refreshToken = getSession('refresh_token')
  if (!refreshToken) {
    showNotice('No refresh token in session.')
    return
  }

  const { request, response, json } = await refreshAccessToken(config, refreshToken)
  appendLog({ title: 'Refresh access token', request, response })

  if (json) {
    setSession('access_token', json.access_token)
    setSession('token_type', json.token_type)
    setSession('expires_in', json.expires_in?.toString())
    if (json.refresh_token) setSession('refresh_token', json.refresh_token)
    refreshStatusStrip()
  }
})

document.getElementById('btn-call-resource').addEventListener('click', async () => {
  hideNotice()
  const config = readConfig()
  const accessToken = getSession('access_token')
  if (!accessToken) {
    showNotice('No access token in session.')
    return
  }

  const { request, response } = await callProtectedResource(config.resourceEndpoint, accessToken)
  appendLog({ title: 'Call protected resource', request, response })
})

document.getElementById('btn-reset').addEventListener('click', () => {
  hideNotice()
  clearSession()
  refreshStatusStrip()
})

document.getElementById('btn-clear-console').addEventListener('click', clearLog)

renderStoredLog()
processRedirectResponse()
refreshStatusStrip()
