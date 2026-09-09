const STORAGE_KEY = 'oauth_test_client.log'

export function appendLog({ title, request, response }) {
  const entry = { title, request, response, time: new Date().toLocaleTimeString() }
  const entries = loadEntries()
  entries.push(entry)
  saveEntries(entries)
  renderEntry(entry)
}

export function clearLog() {
  sessionStorage.removeItem(STORAGE_KEY)
  consoleBody().innerHTML = '<p class="console-placeholder">No requests yet.</p>'
}

export function renderStoredLog() {
  const entries = loadEntries()
  if (entries.length === 0) return
  consoleBody().querySelector('.console-placeholder')?.remove()
  entries.forEach(renderEntry)
}

function block(label, { method, url, status, statusText, headers, body }) {
  const wrap = document.createElement('div')
  wrap.className = 'log-block-wrap'

  const labelEl = document.createElement('span')
  labelEl.className = 'log-block-label'
  labelEl.textContent = label
  wrap.appendChild(labelEl)

  const box = document.createElement('div')
  box.className = 'log-block'

  const mainLine = document.createElement('div')
  mainLine.className = 'log-block-main'
  mainLine.textContent = method ? `${method} ${url}` : `${status} ${statusText}`
  box.appendChild(mainLine)

  const headersEl = document.createElement('pre')
  headersEl.className = 'log-block-headers'
  headersEl.textContent = formatHeaders(headers)
  box.appendChild(headersEl)

  const bodyEl = document.createElement('pre')
  bodyEl.className = 'log-block-body'
  bodyEl.textContent = formatBody(body)
  box.appendChild(bodyEl)

  wrap.appendChild(box)
  return wrap
}

function consoleBody() {
  return document.getElementById('console-body')
}

function formatBody(body) {
  if (!body) return '(empty body)'
  try {
    return JSON.stringify(JSON.parse(body), null, 2)
  } catch {
    return body
  }
}

function formatHeaders(headers) {
  const entries = Object.entries(headers || {})
  if (entries.length === 0) return '(no headers)'
  return entries.map(([key, value]) => `${key}: ${value}`).join('\n')
}

function loadEntries() {
  try {
    return JSON.parse(sessionStorage.getItem(STORAGE_KEY)) || []
  } catch {
    return []
  }
}

function renderEntry({ title, request, response, time }) {
  const container = consoleBody()
  container.querySelector('.console-placeholder')?.remove()

  const entry = document.createElement('div')
  entry.className = 'log-entry'

  const header = document.createElement('div')
  header.className = 'log-entry-header'
  header.innerHTML = `<span class="log-title">${title}</span><span class="log-time">${time}</span>`
  entry.appendChild(header)

  if (request) entry.appendChild(block('Request', request))
  if (response) entry.appendChild(block('Response', response))

  container.appendChild(entry)
  container.scrollTop = container.scrollHeight
}

function saveEntries(entries) {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(entries))
}
