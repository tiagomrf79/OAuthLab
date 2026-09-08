import './style.css'

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
