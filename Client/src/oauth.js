const STORAGE_PREFIX = 'oauth_test_client.'

export function buildAuthorizeUrl({ authorizeEndpoint, clientId, redirectUri, scope }, state) {
  const url = new URL(authorizeEndpoint)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', clientId)
  url.searchParams.set('redirect_uri', redirectUri)
  if (scope) url.searchParams.set('scope', scope)
  url.searchParams.set('state', state)
  return url.toString()
}

export async function callProtectedResource(endpoint, accessToken) {
  const requestHeaders = accessToken ? { Authorization: `Bearer ${accessToken}` } : {}
  const response = await fetch(endpoint, { method: 'GET', headers: requestHeaders })
  const text = await response.text()

  return {
    request: { method: 'GET', url: endpoint, headers: requestHeaders },
    response: {
      status: response.status,
      statusText: response.statusText,
      headers: headersToObject(response.headers),
      body: text,
    },
  }
}

export function clearSession() {
  const sessionKeys = ['state', 'code', 'access_token', 'token_type', 'expires_in', 'refresh_token', 'scope']
  sessionKeys.forEach((key) => sessionStorage.removeItem(STORAGE_PREFIX + key))
}

export function exchangeCodeForToken(config, code) {
  return postForm(
    config.tokenEndpoint,
    { grant_type: 'authorization_code', code, redirect_uri: config.redirectUri },
    config.clientId,
    config.clientSecret,
  )
}

export function getSession(key) {
  return sessionStorage.getItem(STORAGE_PREFIX + key) || ''
}

export function randomString(length = 16) {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function refreshAccessToken(config, refreshToken) {
  return postForm(
    config.tokenEndpoint,
    { grant_type: 'refresh_token', refresh_token: refreshToken },
    config.clientId,
    config.clientSecret,
  )
}

export function setSession(key, value) {
  if (!value) {
    sessionStorage.removeItem(STORAGE_PREFIX + key)
  } else {
    sessionStorage.setItem(STORAGE_PREFIX + key, value)
  }
}

// Client credentials are encoded the same way the OAuth 2 in Action reference
// client does: percent-encode id/secret individually, join with ':', base64 the pair.
function encodeClientCredentials(clientId, clientSecret) {
  return btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`)
}

function headersToObject(headers) {
  const obj = {}
  headers.forEach((value, key) => {
    obj[key] = value
  })
  return obj
}

async function postForm(endpoint, params, clientId, clientSecret) {
  const body = new URLSearchParams(params)
  const requestHeaders = { 'Content-Type': 'application/x-www-form-urlencoded' }
  if (clientId) {
    requestHeaders['Authorization'] = 'Basic ' + encodeClientCredentials(clientId, clientSecret || '')
  }

  const response = await fetch(endpoint, { method: 'POST', headers: requestHeaders, body: body.toString() })
  const text = await response.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {
    // Response wasn't JSON — leave json as null, raw text is still logged.
  }

  return {
    json,
    request: { method: 'POST', url: endpoint, headers: requestHeaders, body: body.toString() },
    response: {
      status: response.status,
      statusText: response.statusText,
      headers: headersToObject(response.headers),
      body: text,
    },
  }
}
