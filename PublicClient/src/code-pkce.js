import './style.css'
import {
  callProtectedResource,
  createStore,
  defaultRedirectUri,
  escapeHtml,
  formatJson,
  randomHex,
  renderLogPanel,
  renderOperationGroup,
  renderStatusItems,
} from './shared.js'

const store = createStore('pkce')

const DEFAULT_CONFIG = {
  authorizeEndpoint: import.meta.env.VITE_AUTHORIZE_ENDPOINT ?? 'http://localhost:5001/authorize',
  tokenEndpoint: import.meta.env.VITE_TOKEN_ENDPOINT ?? 'http://localhost:5001/token',
  resourceEndpoint: import.meta.env.VITE_RESOURCE_ENDPOINT ?? 'http://localhost:5002/resource',
  clientId: import.meta.env.VITE_CLIENT_ID ?? 'public-client',
  scope: import.meta.env.VITE_SCOPE ?? 'read',
  operation: 'read',
}

const CONFIG_FIELDS = ['authorizeEndpoint', 'tokenEndpoint', 'resourceEndpoint', 'clientId', 'redirectUri', 'scope', 'operation']

function getConfig() {
  return {
    authorizeEndpoint: store.get('authorizeEndpoint') ?? DEFAULT_CONFIG.authorizeEndpoint,
    tokenEndpoint: store.get('tokenEndpoint') ?? DEFAULT_CONFIG.tokenEndpoint,
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
    tokenEndpoint: data.get('tokenEndpoint')?.trim() || '',
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

function base64UrlEncode(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// RFC 7636 §4.1: 32 random bytes base64url-encoded gives a 43-char verifier (the minimum length).
function generateCodeVerifier() {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)))
}

// RFC 7636 §4.2: code_challenge = BASE64URL(SHA256(ASCII(code_verifier))).
async function computeS256Challenge(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64UrlEncode(new Uint8Array(digest))
}

async function startAuthorizationRequest(form) {
  const cfg = readFormConfig(form)
  saveConfig(cfg)
  store.remove('code')
  clearTokens()

  const state = randomHex()
  // The verifier never leaves the browser until the back-channel /token call — only its hash goes
  // through the front channel. It lives in sessionStorage so it survives the redirect round-trip.
  const codeVerifier = generateCodeVerifier()
  const codeChallenge = await computeS256Challenge(codeVerifier)
  store.set('state', state)
  store.set('codeVerifier', codeVerifier)
  store.set('codeChallenge', codeChallenge)

  const url = new URL(cfg.authorizeEndpoint)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', cfg.clientId)
  url.searchParams.set('redirect_uri', cfg.redirectUri)
  if (cfg.scope) {
    url.searchParams.set('scope', cfg.scope)
  }
  url.searchParams.set('state', state)
  url.searchParams.set('code_challenge', codeChallenge)
  url.searchParams.set('code_challenge_method', 'S256')

  store.appendLog({
    title: 'Redirect to authorization server',
    request: { method: 'GET', url: url.toString() },
  })

  location.href = url.toString()
}

// The code flow returns its code (and errors) in the query string per RFC 6749 §4.1.2.
function processRedirectResponse() {
  const params = new URLSearchParams(location.search)
  if (!params.has('code') && !params.has('error')) {
    return
  }

  const returnedUrl = location.href
  const expectedState = store.get('state')
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
    return 'State mismatch on return from the authorization server — code discarded.'
  }

  store.set('code', params.get('code') ?? '')
  store.appendLog({
    title: 'Redirect from authorization server',
    response: { method: 'GET', url: returnedUrl },
  })
}

async function exchangeCodeForTokens(form) {
  const cfg = readFormConfig(form)
  saveConfig(cfg)

  const code = store.get('code')
  if (!code) {
    return 'No authorization code yet — run "Start Authorization Request" first.'
  }

  // No Authorization header — this client has no secret. client_id goes in the body instead
  // (token_endpoint_auth_method "none"), and code_verifier proves this is the app that started
  // the request whose code_challenge the AS stored.
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId,
    code_verifier: store.get('codeVerifier') ?? '',
  })
  const request = {
    method: 'POST',
    url: cfg.tokenEndpoint,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  }

  try {
    const response = await fetch(cfg.tokenEndpoint, { method: 'POST', headers: request.headers, body })
    const responseBody = await response.text()

    store.appendLog({
      title: 'Exchange code for tokens',
      request,
      response: {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: formatJson(responseBody),
      },
    })

    if (!response.ok) {
      return 'Token exchange failed — see the log below.'
    }

    const token = JSON.parse(responseBody)
    store.set('accessToken', token.access_token ?? '')
    store.set('tokenType', token.token_type ?? '')
    if (token.expires_in != null) {
      store.set('expiresIn', String(token.expires_in))
    }
    if (token.scope != null) {
      store.set('grantedScope', token.scope)
    }
  } catch (err) {
    store.appendLog({
      title: 'Exchange code for tokens — network error',
      request,
      response: { body: `${err} (likely a CORS or connection issue — is AuthorizationServer running?)` },
    })
    return 'Token exchange failed — see the log below.'
  }
}

function render(error) {
  const cfg = getConfig()

  document.querySelector('#app').innerHTML = `
    <header class="app-header">
      <a href="/" class="back-link">&larr; Home</a>
      <h1>OAuth2 Public Client</h1>
      <p>Authorization Code + PKCE flow playground</p>
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
              Token endpoint
              <input type="text" name="tokenEndpoint" value="${escapeHtml(cfg.tokenEndpoint)}" />
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
              <span class="oauth-action-desc">Generate a code verifier and redirect with its S256 challenge</span>
            </button>
            <button type="button" id="exchange-token-btn" class="oauth-action-btn">
              <span class="oauth-action-title">Exchange Code for Tokens</span>
              <span class="oauth-action-desc">POST the code and code verifier to the token endpoint</span>
            </button>
            <button type="button" id="reset-btn" class="oauth-action-btn secondary">
              <span class="oauth-action-title">Reset Session</span>
              <span class="oauth-action-desc">Clear code, verifier, tokens and state</span>
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
              ['State', store.get('state')],
              ['Code verifier', store.get('codeVerifier')],
              ['Code challenge', store.get('codeChallenge')],
              ['Authorization code', store.get('code')],
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

  document.querySelector('#exchange-token-btn').addEventListener('click', async () => {
    render(await exchangeCodeForTokens(form))
  })

  document.querySelector('#call-resource-btn').addEventListener('click', async () => {
    const cfg = readFormConfig(form)
    saveConfig(cfg)
    await callProtectedResource(store, cfg.resourceEndpoint, cfg.operation, store.get('accessToken'))
    render()
  })

  document.querySelector('#reset-btn').addEventListener('click', () => {
    store.remove('state', 'codeVerifier', 'codeChallenge', 'code')
    clearTokens()
    render()
  })

  document.querySelector('#clear-log-btn').addEventListener('click', () => {
    store.clearLogs()
    render()
  })
}

render(processRedirectResponse())
