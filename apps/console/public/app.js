const state = {
  events: [],
  seen: new Set(),
  filter: 'all',
  query: '',
  auditPath: '',
  replay: null,
  bench: null,
}

const $ = (id) => document.getElementById(id)

const escapeHtml = (value) =>
  String(value).replace(/[&<>"']/g, (char) => {
    switch (char) {
      case '&': return '&amp;'
      case '<': return '&lt;'
      case '>': return '&gt;'
      case '"': return '&quot;'
      default: return '&#39;'
    }
  })

const decisions = () =>
  state.events.filter((event) => event.type === 'decision.made')

function addEvent(event) {
  if (!event || !event.hash || state.seen.has(event.hash)) return false
  state.seen.add(event.hash)
  state.events.push(event)
  return true
}

function actionLabel(action) {
  if (!action) return 'unknown action'
  if (action.kind === 'process.exec') return `$ ${action.command ?? ''}`
  if (action.kind === 'fs.read') return `read ${action.path ?? ''}`
  if (action.kind === 'fs.write') return `write ${action.path ?? ''}`
  if (action.kind === 'network.connect') return `network ${action.target ?? ''}`
  return `${action.kind} ${action.tool ?? ''}`
}

function badge(kind) {
  const label = kind === 'deny' ? 'DENY' : kind === 'ask' ? 'ASK' : 'ALLOW'
  return `<span class="badge ${kind}">${label}</span>`
}

function riskPill(level) {
  return `<span class="risk ${level}">${escapeHtml(level)}</span>`
}

function renderMetrics() {
  const all = decisions()
  const denied = all.filter((event) => event.payload?.decision?.kind === 'deny').length
  const asked = all.filter((event) => event.payload?.decision?.kind === 'ask').length
  const allowed = all.filter((event) => event.payload?.decision?.kind === 'allow').length
  const latencies = all
    .map((event) => Number(event.payload?.decision?.latencyMs ?? 0))
    .sort((a, b) => a - b)
  const p95 = latencies.length
    ? latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * 0.95))]
    : 0

  $('metrics').innerHTML = `
    <div class="metric"><label>decisions</label><strong>${all.length}</strong></div>
    <div class="metric deny"><label>denied</label><strong>${denied}</strong></div>
    <div class="metric ask"><label>asked</label><strong>${asked}</strong></div>
    <div class="metric allow"><label>allowed</label><strong>${allowed}</strong></div>
    <div class="metric"><label>p95 decision</label><strong>${p95.toFixed(2)} ms</strong></div>
  `
}

function renderTimeline() {
  const all = decisions()
  const query = state.query
  const visible = all
    .filter(
      (event) =>
        state.filter === 'all' ||
        event.payload?.decision?.kind === state.filter,
    )
    .filter(
      (event) =>
        query === '' ||
        JSON.stringify(event.payload).toLowerCase().includes(query),
    )

  $('count').textContent = `${visible.length}/${all.length}`

  if (visible.length === 0) {
    $('timeline').innerHTML = '<p class="muted">No matching decisions.</p>'
    return
  }

  $('timeline').innerHTML = visible
    .map((event) => {
      const decision = event.payload.decision
      const policies = (decision.policyIds ?? [])
        .map((id) => `<code>${escapeHtml(id)}</code>`)
        .join(' ')
      return `
        <article class="event ${decision.kind}">
          <div class="event-head">
            <span class="seq">#${event.seq}</span>
            ${badge(decision.kind)}
            ${riskPill(decision.risk?.level ?? 'low')}
            <span class="latency">${Number(decision.latencyMs ?? 0).toFixed(2)} ms</span>
          </div>
          <div class="command">${escapeHtml(actionLabel(event.payload.action))}</div>
          <div class="reason">${escapeHtml(decision.reason ?? '')}</div>
          <div class="policies">${policies}</div>
        </article>`
    })
    .join('')
}

function renderTaint() {
  const taintEvent = state.events.find((event) => event.type === 'session.tainted')
  const fallbackSource = decisions()
    .flatMap((event) => event.payload?.state?.taintSources ?? [])
    .find(Boolean)
  const hasTaint = Boolean(taintEvent || fallbackSource)

  if (!hasTaint) {
    $('taint').innerHTML = '<p class="muted">No taint recorded yet.</p>'
    return
  }

  const blocked = decisions().find((event) =>
    (event.payload?.decision?.policyIds ?? []).includes('deny-tainted-egress'),
  )
  const secret =
    taintEvent?.payload?.source?.path ??
    fallbackSource?.path ??
    fallbackSource?.id?.slice(0, 12) ??
    'secret'

  const pills = []
  if (taintEvent?.payload?.sandboxMode) {
    pills.push(`<span class="pill on">sandbox: ${escapeHtml(taintEvent.payload.sandboxMode)}</span>`)
  }
  if (taintEvent?.payload?.networkIsolation) {
    pills.push(`<span class="pill on">network: ${escapeHtml(taintEvent.payload.networkIsolation)}</span>`)
  }
  if (taintEvent?.payload?.egressProxy) {
    pills.push('<span class="pill on">egress proxy: on</span>')
  }

  $('taint').innerHTML = `
    <div class="chain-row">
      <div class="node secret"><small>SECRET</small>${escapeHtml(secret)}</div>
      <div class="arrow">read</div>
      <div class="node taint"><small>SESSION</small>tainted</div>
      ${
        blocked
          ? `<div class="arrow">egress</div><div class="node blocked"><small>BLOCKED</small>${escapeHtml(actionLabel(blocked.payload.action))}</div>`
          : '<div class="arrow">no egress attempt</div>'
      }
    </div>
    ${pills.length ? `<div class="meta-row">${pills.join('')}</div>` : ''}
  `
}

function replayBlock(report, label) {
  if (!report) return ''
  const percent = report.total > 0 ? Math.round((report.matched / report.total) * 100) : 100
  const mismatches = (report.mismatches ?? [])
    .map(
      (mismatch) =>
        `<li>seq ${mismatch.seq}: recorded <code>${escapeHtml(mismatch.expected)}</code> → replayed <code>${escapeHtml(mismatch.actual)}</code></li>`,
    )
    .join('')
  return `
    <div class="replay-row">
      <div class="replay-head">
        <span>${escapeHtml(label)}</span>
        <strong>${report.matched}/${report.total} matched</strong>
      </div>
      <div class="bar"><span style="width:${percent}%"></span></div>
      ${mismatches ? `<ul class="mismatches">${mismatches}</ul>` : ''}
    </div>`
}

function renderReplay() {
  if (!state.replay) {
    $('replay').innerHTML =
      '<p class="muted">Run <code>pnpm demo</code> to populate replay data.</p>'
    return
  }
  $('replay').innerHTML =
    replayBlock(state.replay.same, 'with recorded approvals') +
    replayBlock(state.replay.withoutApprovals, 'after approvals revoked')
}

function renderBench() {
  const bench = state.bench
  if (!bench) {
    $('bench').innerHTML =
      '<p class="muted">Run <code>pnpm bench</code> to populate benchmark data.</p>'
    return
  }
  $('bench').innerHTML = `
    <div class="bench-metrics">
      <div><small>ATTACKS BLOCKED</small><strong>${bench.attacks.blocked}/${bench.attacks.total}</strong></div>
      <div><small>HARD FALSE POSITIVES</small><strong>${bench.benign.denied}/${bench.benign.total}</strong></div>
      <div><small>P95 DECISION</small><strong>${bench.latency.p95.toFixed(2)} ms</strong></div>
      <div><small>KNOWN GAPS</small><strong>${bench.knownGaps.missed}/${bench.knownGaps.total}</strong></div>
    </div>
    <p class="muted">Known gaps are reported separately; L2/L2.5/L2.6 harden the layers above them.</p>
  `
}

function renderAll() {
  $('audit-path').textContent = state.auditPath
  renderMetrics()
  renderTimeline()
  renderTaint()
  renderReplay()
  renderBench()
}

function setLive(ok) {
  const live = $('live')
  live.classList.toggle('ok', ok)
  live.classList.toggle('bad', !ok)
  $('live-text').textContent = ok ? 'live' : 'reconnecting…'
}

async function load() {
  const response = await fetch('/api/state', { cache: 'no-store' })
  const data = await response.json()
  state.events = []
  state.seen.clear()
  for (const event of data.events ?? []) addEvent(event)
  state.replay = data.replay
  state.bench = data.bench
  state.auditPath = data.auditPath ?? ''
  renderAll()
}

function connect() {
  const source = new EventSource('/api/stream')

  source.addEventListener('hello', (event) => {
    try {
      const data = JSON.parse(event.data)
      if (data.auditPath) {
        state.auditPath = data.auditPath
        $('audit-path').textContent = data.auditPath
      }
    } catch {
      // ignore
    }
    setLive(true)
  })

  source.onmessage = (event) => {
    try {
      const parsed = JSON.parse(event.data)
      if (addEvent(parsed)) renderAll()
      setLive(true)
    } catch {
      // ignore partial frames
    }
  }

  source.onerror = () => setLive(false)
}

document.querySelectorAll('[data-filter]').forEach((button) => {
  button.addEventListener('click', () => {
    state.filter = button.dataset.filter
    document.querySelectorAll('[data-filter]').forEach((candidate) => {
      candidate.classList.toggle('active', candidate === button)
    })
    renderTimeline()
  })
})

$('search').addEventListener('input', (event) => {
  state.query = event.target.value.trim().toLowerCase()
  renderTimeline()
})

load()
  .then(connect)
  .catch((error) => {
    $('timeline').innerHTML = `<p class="muted">Failed to load: ${escapeHtml(error.message)}</p>`
    setLive(false)
  })
