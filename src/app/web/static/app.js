'use strict';
const $ = (s) => document.querySelector(s),
  $$ = (s) => [...document.querySelectorAll(s)];
const esc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
const state = {
  report: null,
  project: null,
  view: 'overview',
  phase: 'candidate',
  config: null,
  reduction: null,
  repair: null,
  mutation: null,
  coverage: null,
  labelResult: null,
  labelEndpoint: null,
  queryResult: null,
  draftCheckResult: null,
  history: [],
  selected: null,
  job: null,
  filter: { text: '', change: 'ALL', verdict: 'ALL' },
  limit: 60,
  busy: false,
};
const names = {
  overview: 'Overview',
  connections: 'Connections',
  containment: 'Containment lab',
  experiments: 'Experiments',
  evidence: 'Evidence',
  inputs: 'Inputs & history',
};
// Remember only the saved review ID. Inputs and credentials stay on the server.
function rememberRun(id) {
  try {
    localStorage.setItem('netscope.lastRun', id);
  } catch {
    // Storage can be disabled; the workspace remains usable.
  }
}
function lastRun() {
  try {
    return localStorage.getItem('netscope.lastRun');
  } catch {
    return null;
  }
}
async function api(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.method ? { 'X-NetScope-Token': state.config.token } : {}),
    ...options.headers,
  };
  const r = await fetch(path, { ...options, headers });
  if (!r.ok) {
    let e;
    try {
      e = await r.json();
    } catch {
      e = { detail: r.statusText };
    }
    throw new Error(typeof e.detail === 'string' ? e.detail : JSON.stringify(e.detail));
  }
  return r.json();
}
function notice(error) {
  $('#notice').textContent = error?.message || String(error);
  $('#notice').hidden = false;
}
function toast(message) {
  const e = $('#toast');
  e.textContent = message;
  e.classList.add('visible');
  setTimeout(() => e.classList.remove('visible'), 3500);
}
async function task(button, work) {
  if (state.busy) return;
  state.busy = true;
  $('#notice').hidden = true;
  const old = button?.textContent;
  if (button) {
    button.disabled = true;
    button.textContent = 'Working…';
  }
  try {
    await work();
  } catch (e) {
    notice(e);
  } finally {
    state.busy = false;
    if (button?.isConnected) {
      button.disabled = false;
      button.textContent = old;
    }
  }
}
function pill(v) {
  const color = ['Allow', 'PASS', 'COMPLETE', 'VERIFIED_ON_SCOPE'].includes(v)
    ? 'good'
    : ['Deny', 'FAIL', 'UNEXPECTED_REACHABILITY'].includes(v)
      ? 'bad'
      : ['Unknown', 'INCOMPLETE', 'INCONCLUSIVE', 'INTERRUPTED', 'CANCELLED'].includes(v)
        ? 'warn'
        : 'neutral';
  return `<span class="pill ${color}">${esc(v)}</span>`;
}
function delta(v) {
  const text = {
    NEWLY_ALLOWED: '↗ Newly allowed',
    NEWLY_BLOCKED: '↘ Newly blocked',
    UNCHANGED: '— Unchanged',
    UNKNOWN: '? Unknown',
  };
  return `<span class="delta ${v === 'NEWLY_BLOCKED' ? 'blocked' : v === 'UNKNOWN' ? 'unknown' : v === 'UNCHANGED' ? 'unchanged' : ''}">${text[v] || esc(v)}</span>`;
}
const endpoint = (v) => {
  const parts = v.split('/');
  return `<span class="endpoint">${esc(parts.slice(1).join('/'))}<small>${esc(parts[0])}</small></span>`;
};
function metric(label, value, foot, color = '') {
  return `<div class="metric ${color}"><div class="metric-label">${esc(label)}<span>↗</span></div><div class="metric-value">${esc(value)}</div><div class="metric-foot">${esc(foot)}</div></div>`;
}
function formatDate(v) {
  return new Date(v).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}
function goto(view) {
  if (!names[view]) view = 'overview';
  state.view = view;
  location.hash = view;
  render();
}
async function runProject(raw) {
  const r = await api('/api/runs', { method: 'POST', body: JSON.stringify({ project: raw }) });
  state.report = r;
  state.project = await api(`/api/runs/${r.id}/project`);
  state.reduction = null;
  state.repair = null;
  state.mutation = null;
  state.coverage = null;
  state.labelResult = null;
  state.labelEndpoint = null;
  state.queryResult = null;
  state.draftCheckResult = null;
  state.job = null;
  state.selected = null;
  state.limit = 60;
  state.history = await api('/api/runs');
  rememberRun(r.id);
  render();
  toast(`Review complete · ${r.stats.queries} queries · ${r.status.toLowerCase()}`);
}
async function openRun(id) {
  state.report = await api('/api/runs/' + id);
  state.project = await api(`/api/runs/${id}/project`);
  state.reduction = null;
  state.repair = null;
  state.mutation = null;
  state.coverage = null;
  state.labelResult = null;
  state.labelEndpoint = null;
  state.queryResult = null;
  state.draftCheckResult = null;
  state.job = null;
  state.selected = null;
  state.limit = 60;
  rememberRun(id);
  render();
}
function render() {
  const r = state.report;
  if (!r) return;
  $('#project-name').textContent = r.name;
  $('#project-description').textContent = r.description;
  $('#breadcrumb').textContent = names[state.view];
  $$('#nav button').forEach((b) => b.classList.toggle('active', b.dataset.view === state.view));
  $('#nav-count').textContent = r.stats.queries;
  $('#run-fingerprint').textContent = `${r.id.slice(0, 8)} / SHA-256 ${r.input_hash.slice(0, 16)}`;
  $('#export-json').href = `/api/runs/${r.id}/report.json`;
  $('#export-html').href = `/api/runs/${r.id}/report.html`;
  $('#view-container').innerHTML = { overview, connections, containment, experiments, evidence, inputs }[
    state.view
  ]();
  bindView();
  bindExtraExperiments();
  if (state.labelResult && $('#label-editor'))
    $('#label-editor').value = JSON.stringify(state.labelResult.labels_after, null, 2);
}
function intentList() {
  return (
    state.report.intents
      .map(
        (i) =>
          `<div class="intent-item"><span class="intent-icon ${i.candidate.status === 'FAIL' ? 'fail' : i.candidate.status !== 'PASS' ? 'unknown' : ''}">${i.candidate.status === 'PASS' ? '✓' : i.candidate.status === 'FAIL' ? '✕' : '?'}</span><div class="intent-text"><strong>${esc(i.intent_id)}</strong><small>${esc(i.expectation)} · ${i.matched_count} matched</small></div><span class="intent-count">${esc(i.candidate.status)}</span></div>`,
      )
      .join('') || '<p class="subtle">No application intents. Required behaviour cannot be certified.</p>'
  );
}
function graph() {
  const r = state.report;
  const nodes = r.nodes;
  const groups = [...new Set(nodes.map((n) => n.namespace))];
  let positions = {};
  const w = 690,
    h = 300;
  const col = w / (groups.length + 1);
  groups.forEach((ns, ix) => {
    const members = nodes.filter((n) => n.namespace === ns);
    members.forEach(
      (n, j) => (positions[n.id] = { x: col * (ix + 1), y: 55 + (j + 0.5) * (215 / members.length) }),
    );
  });
  const picked = new Set([
    ...r.intents.flatMap((i) => i.matched_tuples),
    ...r.rows.filter((x) => x.change !== 'UNCHANGED').map((x) => x.tuple_id),
    ...r.threat.findings.flatMap((p) => p.hops.map((h) => h.tuple_id)),
  ]);
  const edges = r.rows
    .filter((x) => picked.has(x.tuple_id) && positions[x.source] && positions[x.destination])
    .slice(0, 24);
  const pathIDs = new Set(r.threat.findings.flatMap((p) => p.hops.map((x) => x.tuple_id)));
  let edgeSVG = edges
    .map((e, i) => {
      const a = positions[e.source],
        b = positions[e.destination],
        allowed = e[state.phase] === 'Allow',
        changed = e.change !== 'UNCHANGED',
        path = pathIDs.has(e.tuple_id) && state.phase === 'candidate';
      const color = path ? '#eac67a' : allowed ? (changed ? '#64dcba' : '#387e79') : '#566478';
      const sx = a.x + (a.x < b.x ? 59 : a.x > b.x ? -59 : 0),
        sy = a.y + (a.x === b.x ? (a.y < b.y ? 16 : -16) : 0),
        tx = b.x + (a.x < b.x ? -61 : a.x > b.x ? 61 : 0),
        ty = b.y + (a.x === b.x ? (a.y < b.y ? -18 : 18) : 0);
      const same = a.x === b.x;
      const midX = same ? Math.min(w - 20, a.x + 110 + (i % 3) * 12) : (sx + tx) / 2;
      const midY = (sy + ty) / 2 + (same ? 0 : ((i % 3) - 1) * 20);
      return `<path d="M ${sx} ${sy} C ${midX} ${same ? sy : midY}, ${midX} ${same ? ty : midY}, ${tx} ${ty}" fill="none" stroke="${color}" stroke-width="${path ? 2.5 : 1.2}" ${allowed ? '' : 'stroke-dasharray="4 5"'} opacity="${path ? 1 : 0.65}" marker-end="url(#${path ? 'arrow-path' : allowed ? 'arrow-allow' : 'arrow-deny'})"><title>${esc(e.source)} → ${esc(e.destination)} ${e.protocol}/${e.port}: ${esc(e[state.phase])}</title></path>`;
    })
    .join('');
  const groupSVG = groups
    .map(
      (ns, i) =>
        `<rect x="${col * (i + 1) - 77}" y="34" width="154" height="239" rx="10" fill="#101d2b" fill-opacity=".45" stroke="#26394b" stroke-dasharray="3 6"/><text x="${col * (i + 1)}" y="23" text-anchor="middle" fill="#6d94aa" font-family="monospace" font-size="9">${esc(ns.toUpperCase())} NAMESPACE</text>`,
    )
    .join('');
  const nodeSVG = nodes
    .map((n) => {
      const { x, y } = positions[n.id];
      const type =
        n.role === 'agent'
          ? 'AGENT'
          : n.role === 'asset'
            ? 'DATA ASSET'
            : n.role === 'tool'
              ? 'TOOL'
              : 'WORKLOAD';
      const color = n.role === 'agent' ? '#64d8b1' : n.role === 'asset' ? '#dfc07f' : '#88aeca';
      return `<g class="node" tabindex="0" role="button" data-node="${esc(n.id)}" aria-label="Inspect connections for ${esc(n.id)}"><rect x="${x - 59}" y="${y - 18}" width="118" height="36" rx="7" fill="#172a3a" stroke="${n.role === 'asset' ? '#62563a' : n.role === 'agent' ? '#326d5b' : '#314b61'}"/><circle cx="${x - 47}" cy="${y - 2}" r="3" fill="${color}"/><text x="${x - 37}" y="${y - 2}" fill="#dbe8f2" font-family="system-ui" font-size="10">${esc(n.name)}</text><text x="${x - 37}" y="${y + 10}" fill="${color}" font-family="monospace" font-size="6.5" letter-spacing="1">${type}</text></g>`;
    })
    .join('');
  return `<div class="panel graph-panel"><div class="graph-toolbar"><h2 style="font-size:13px">Connectivity map <span class="subtle">/ selected review paths</span></h2><div class="tabs"><button data-phase="baseline" class="${state.phase === 'baseline' ? 'active' : ''}">Baseline</button><button data-phase="candidate" class="${state.phase === 'candidate' ? 'active' : ''}">Candidate</button></div></div><div class="graph-wrap"><svg class="network" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(state.phase)} network model. Selected intent, changed, and containment paths; use Connections for full scope."><defs>${[
    ['allow', '#438e81'],
    ['deny', '#657185'],
    ['path', '#eac67a'],
  ]
    .map(
      ([id, c]) =>
        `<marker id="arrow-${id}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="${c}"/></marker>`,
    )
    .join(
      '',
    )}</defs>${groupSVG}${edgeSVG}${nodeSVG}</svg></div><div class="graph-legend"><span><i class="legend-line"></i>Allowed</span><span><i class="legend-line deny"></i>Denied</span><span><i class="legend-line path"></i>Conditional containment path</span><span>Known policy decisions · not live traffic</span></div></div>`;
}
function overview() {
  const r = state.report,
    s = r.stats,
    newPaths = r.threat.findings.filter((p) => p.new).length;
  const hero = newPaths
    ? {
        title: s.intent_fail
          ? 'An indirect asset path opens, too.'
          : 'Direct checks pass. An indirect path opens.',
        text: `${s.intent_pass} application intents pass; ${s.intent_fail} fail. Declared relay assumptions create ${newPaths} new sensitive-asset exposure(s). See every hop and the assumption behind it.`,
        tag: 'THE CONSEQUENCE BEHIND THE CHANGE',
        action: 'Inspect containment path →',
        view: 'containment',
      }
    : s.intent_fail
      ? {
          title: `${s.intent_fail} application intents are broken.`,
          text: 'A small policy edit changed application behaviour. Inspect its rule trace, then export a smaller model-preserved reproduction.',
          tag: 'REGRESSION DETECTED',
          action: 'Open regression experiments →',
          view: 'experiments',
        }
      : s.UNKNOWN
        ? {
            title: 'Uncertainty is a result, too.',
            text: 'An unsupported construct can influence these decisions. The model refuses to issue a complete pass.',
            tag: 'HONEST COVERAGE',
            action: 'Inspect query coverage →',
            view: 'connections',
          }
        : {
            title: 'A clean review. Now challenge it.',
            text: 'The declared candidate intents pass. Inject selector and port mistakes to find gaps in your intent suite.',
            tag: 'FAULT-INJECTION READY',
            action: 'Launch experiments →',
            view: 'experiments',
          };
  return `<div class="metrics">${metric('SEMANTIC CHANGES', s.NEWLY_ALLOWED + s.NEWLY_BLOCKED, `${s.NEWLY_ALLOWED} opened · ${s.NEWLY_BLOCKED} blocked`, 'green')}${metric('APPLICATION INTENTS', `${s.intent_pass} / ${r.intents.length}`, `${s.intent_fail} failed · candidate revision`, s.intent_fail ? 'red' : 'cyan')}${metric('CONTAINMENT PATHS', r.threat.findings.length, `${newPaths} new · under explicit assumptions`, 'amber')}${metric('REVIEW GATE', r.status, `Exit ${r.exit_code} · ${s.queries} declared queries`, r.exit_code === 0 ? 'green' : r.exit_code === 1 ? 'red' : 'amber')}</div>
 ${demoGuide()}<div class="grid-main"><div>${graph()}<div class="panel"><div class="section-line"><h2>What changed?</h2><button class="link-button" data-goto="connections">All connections ↗</button></div>${changedTable()}</div></div><div><div class="insight-card"><div class="eyebrow">${hero.tag}</div><h3>${hero.title}</h3><p>${hero.text}</p><button class="small-button" data-goto="${hero.view}">${hero.action}</button></div><div class="panel"><div class="section-line"><h2>Application intent</h2><span class="subtle">Candidate</span></div>${intentList()}</div></div></div>
 <div class="insights-row"><div class="panel"><div class="section-line"><h2>From change to evidence</h2><span class="pill neutral">REPEATABLE</span></div><div class="fact-row"><span class="fact-index">01</span><p><strong>Compare behaviour, not YAML text</strong>Order-only edits create no semantic delta.</p></div><div class="fact-row"><span class="fact-index">02</span><p><strong>Preserve a failure while removing context</strong>Reduce paired policies; keep the exact decision and isolation signature.</p></div><div class="fact-row"><span class="fact-index">03</span><p><strong>Verify in an isolated lab</strong>Healthy controls, fresh connections, and explicit incomplete results.</p></div></div><div class="panel"><h2 style="margin-bottom:15px">Run provenance</h2><div class="data-pair"><span>Input fingerprint</span><code>${r.input_hash.slice(0, 20)}…</code></div><div class="data-pair"><span>Modelled endpoints</span><strong>${s.endpoints} / ${[...new Set(r.nodes.map((n) => n.namespace))].length} namespaces</strong></div><div class="data-pair"><span>Analysis time</span><strong>${s.duration_ms} ms</strong></div><div class="data-pair"><span>Runtime evidence</span><strong class="warning-text">Not verified</strong></div><p class="help">${esc(r.gate_reasons.join(' · ') || 'All declared candidate checks pass. This is a static result.')}</p></div></div>`;
}
function demoGuide() {
  return `<details class="panel demo-guide"><summary>Presenter guide · a five-minute walkthrough</summary><ol><li><strong>Show the surprise.</strong> Load the agent example: five direct intents pass, but one conditional asset path opens. <button class="small-button" data-load="agent-escape">Load agent example</button></li><li><strong>Challenge the assumption.</strong> Open the containment lab, inspect each hop, then remove one relay assumption. Policy permissions stay the same. <button class="small-button" data-goto="containment">Inspect containment</button></li><li><strong>Find a constrained repair.</strong> Search small baseline reverts and open a fully re-evaluated proposal. <button class="small-button" data-goto="experiments">Open experiments</button></li><li><strong>Make the regression portable.</strong> Load the database switch, reduce a changed connection, and export its replay bundle. <button class="small-button" data-load="checkout-regression">Load regression</button></li></ol><p class="help">Say explicitly: these are finite static results; real Kubernetes/CNI enforcement remains unverified. See docs/DEMO_SCRIPT.md for questions and answers.</p></details>`;
}
function changedTable() {
  const rows = state.report.rows.filter((r) => r.change !== 'UNCHANGED');
  if (!rows.length) return '<p class="help">No semantic changes on the declared query set.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Connection</th><th>Port</th><th>Before → After</th></tr></thead><tbody>${rows
    .slice(0, 6)
    .map(
      (r) =>
        `<tr data-row="${r.tuple_id}" tabindex="0"><td>${endpoint(r.source)} <span class="muted">→</span> ${endpoint(r.destination)}</td><td class="mono">${r.protocol}/${r.port}</td><td>${pill(r.baseline)} <span class="muted">→</span> ${pill(r.candidate)}</td></tr>`,
    )
    .join('')}</tbody></table></div>`;
}
function filteredRows() {
  const f = state.filter;
  return state.report.rows.filter(
    (r) =>
      (f.change === 'ALL' || r.change === f.change) &&
      (f.verdict === 'ALL' || r.candidate === f.verdict) &&
      `${r.source} ${r.destination} ${r.protocol} ${r.port} ${r.tuple_id}`
        .toLowerCase()
        .includes(f.text.toLowerCase()),
  );
}
function connections() {
  const rows = filteredRows();
  return `<div class="section-line"><div><h2>Every connection. Both directions.</h2><div class="subtle">Select a row for matching policy rules, isolation state, and endpoint labels.</div></div><span class="pill neutral">${state.report.stats.queries} QUERIES</span></div><div class="toolbar"><label class="sr-only" for="search">Filter by endpoint, protocol, port or tuple ID</label><input id="search" placeholder="Search endpoints, protocol, port…" value="${esc(state.filter.text)}"><select id="change-filter" aria-label="Change filter">${['ALL', 'NEWLY_ALLOWED', 'NEWLY_BLOCKED', 'UNCHANGED', 'UNKNOWN'].map((v) => `<option ${v === state.filter.change ? 'selected' : ''} value="${v}">${v === 'ALL' ? 'All changes' : v.toLowerCase().replaceAll('_', ' ')}</option>`).join('')}</select><select id="verdict-filter" aria-label="Candidate decision filter">${['ALL', 'Allow', 'Deny', 'Unknown'].map((v) => `<option ${v === state.filter.verdict ? 'selected' : ''} value="${v}">${v === 'ALL' ? 'All decisions' : v}</option>`).join('')}</select></div><div class="panel flush"><div class="table-wrap"><table><thead><tr><th>Source</th><th>Destination</th><th>Protocol / Port</th><th>Baseline</th><th>Candidate</th><th>Semantic delta</th></tr></thead><tbody id="connections-body">${connectionRows(rows)}</tbody></table></div><div class="table-footer"><span id="row-count">Showing ${Math.min(state.limit, rows.length)} of ${rows.length} matching queries</span><button class="small-button" id="more-rows" ${state.limit >= rows.length ? 'hidden' : ''}>Show 60 more</button></div></div><p class="help">Unknown and unqueried paths are never silently treated as Deny. All intent-matched tuples are added to the scope, even with an explicit query list.</p>${queryComposer()}`;
}
function connectionRows(rows) {
  return (
    rows
      .slice(0, state.limit)
      .map(
        (r) =>
          `<tr data-row="${r.tuple_id}" tabindex="0" aria-label="Inspect ${esc(r.source)} to ${esc(r.destination)} ${r.protocol}/${r.port}"><td>${endpoint(r.source)}</td><td>${endpoint(r.destination)}</td><td class="mono">${r.protocol} <span class="muted">/</span> ${r.port}</td><td>${pill(r.baseline)}</td><td>${pill(r.candidate)}</td><td>${delta(r.change)}</td></tr>`,
      )
      .join('') || '<tr><td colspan="6" class="muted">No queries match these filters.</td></tr>'
  );
}
function assumptionEvidence(p) {
  if (!p.assumption_checks) return '';
  const checks = p.assumption_checks.length
    ? p.assumption_checks
        .map(
          (c) =>
            `<div class="sensitivity-check"><strong>Without ${esc(c.pivot)} as a relay</strong><p>${c.asset_still_reachable ? `An alternative ${c.alternative_hops.length}-hop path still reaches this asset. Removing this one assumption is insufficient.` : 'No path to this asset is found after searching all other declared routes within four hops.'}</p><button class="small-button" data-remove-pivot="${esc(c.pivot)}">Open this counterfactual →</button></div>`,
        )
        .join('')
    : '<p class="help">This is a direct path. Removing relay assumptions cannot remove it.</p>';
  const missing = (p.port_evidence || []).filter((h) => h.declaration === 'not-declared');
  return `<details class="assumption-evidence" open><summary>Which assumptions matter?</summary>${checks}<p class="help">${missing.length ? `${missing.length} destination port(s) are absent from the workload declarations. This path describes policy permission; listener availability needs separate evidence.` : 'All destination ports appear in the workload declarations. A declaration still does not prove a running listener.'}</p></details>`;
}
function containment() {
  const t = state.report.threat;
  if (!t.enabled)
    return `<div class="panel"><h2>Make the assumptions explicit.</h2><p class="subtle">This input has no threat model. Load “The indirect escape” to explore agent → gateway → database, or declare entrypoints, pivots, and assets in Inputs.</p><button class="primary" data-load="agent-escape">Load agent-containment scenario</button></div>`;
  return `<div class="section-line"><div><h2>Could a compromised agent reach the asset?</h2><div class="subtle">An application-aware experiment beyond direct connectivity intent.</div></div><span class="pill warn">CONDITIONAL EXPOSURE</span></div><div class="alert">${esc(t.warning)}</div><div class="metrics">${metric('BASELINE REACHABLE', t.baseline.reachable_pairs, 'Entry-point / endpoint pairs', 'cyan')}${metric('CANDIDATE REACHABLE', t.candidate.reachable_pairs, 'Within four hops', 'amber')}${metric('SENSITIVE-ASSET PATHS', t.findings.length, 'Shortest witnessed paths', 'red')}${metric('DECLARED PIVOTS', t.pivots.length, 'No automatic exploitation assumption', 'green')}</div><div class="threat-grid"><div>${t.findings.length ? t.findings.map((p) => `<div class="path-card"><div class="section-line"><h3>${p.new ? 'New sensitive-asset exposure' : 'Existing sensitive-asset exposure'}</h3>${pill(p.new ? 'NEW PATH' : 'EXISTING')}</div><div class="path-flow"><span class="path-node">${esc(p.entrypoint)}</span>${p.hops.map((h) => `<span class="path-arrow">→<small>${h.protocol}/${h.port}</small></span><button class="path-node ${h.destination === p.asset ? 'asset' : ''}" data-row="${h.tuple_id}">${esc(h.destination)}</button>`).join('')}</div><div class="assumptions"><strong>Conditions behind this path</strong><ul>${p.assumptions.map((a) => `<li>${esc(a)}</li>`).join('')}</ul></div><p class="help">Each edge has a known Allow decision. Click a hop to inspect both policy directions.</p>${assumptionEvidence(p)}</div>`).join('') : '<div class="panel"><h3>No asset path found within this model.</h3><p class="subtle">This does not prove that omitted endpoints, credentials, or unqueried traffic are safe.</p></div>'}<div class="panel"><h2>What if none of the workloads can relay?</h2><p class="help">This changes the declared pivot assumption in a new run. It does not change NetworkPolicy permissions.</p><button id="no-pivots">Re-evaluate without pivot assumptions →</button></div></div><div><div class="panel"><h2>Blast-radius comparison</h2>${t.entrypoints
    .map((e) => {
      const b = t.baseline.radius[e]?.length || 0,
        c = t.candidate.radius[e]?.length || 0,
        max = Math.max(1, state.report.nodes.length - 1);
      return `<p class="mono" style="margin-top:18px">${esc(e)}</p><div class="data-pair"><span>Baseline</span><strong>${b} endpoints</strong></div><div class="radius-bar"><span style="width:${(100 * b) / max}%;background:#5b93b0"></span></div><div class="data-pair"><span>Candidate</span><strong>${c} endpoints</strong></div><div class="radius-bar"><span style="width:${(100 * c) / max}%;background:#edc276"></span></div>`;
    })
    .join(
      '',
    )}<p class="help">${esc(t.scope)}</p></div><div class="panel"><h2>Containment assumptions</h2><div class="data-pair"><span>Entry points</span><strong>${t.entrypoints.length}</strong></div><div class="data-pair"><span>Relay / pivot workloads</span><strong>${t.pivots.length}</strong></div><div class="data-pair"><span>Sensitive assets</span><strong>${t.assets.length}</strong></div><p class="help">${esc(t.sensitivity_scope || '')}</p><p class="help">RBAC permissions, application authentication, CVEs, and prompt injection are outside this network model.</p><button class="small-button" data-goto="experiments">Find a scoped containment repair →</button></div>${state.report.posture.length ? `<div class="alert">${state.report.posture.map((p) => `${esc(p.endpoint)}: ${esc(p.message)}`).join('<br>')}</div>` : ''}</div></div>`;
}
function experiments() {
  const changed = state.report.rows.filter((r) => ['NEWLY_ALLOWED', 'NEWLY_BLOCKED'].includes(r.change));
  return `<div class="section-line"><div><h2>Small experiments. Defensible conclusions.</h2><div class="subtle">Every proposal stays local. No experiment deploys or edits your saved review.</div></div></div><div class="experiment-grid"><div class="panel"><div class="experiment-head"><div class="experiment-icon">⇣</div><div><h2>Regression reducer</h2><p>Turn a large policy change into a replayable case.</p></div></div><p class="experiment-body">Remove policies from both revisions while preserving the selected before/after decisions, isolation flags, and failing candidate intents. Fixed topology; no global-minimum claim.</p><select class="reducer-select" id="witness" aria-label="Connection to reduce">${changed.map((r) => `<option value="${r.tuple_id}">${esc(r.source)} → ${esc(r.destination)} · ${r.protocol}/${r.port}</option>`).join('') || '<option>No supported changed connection</option>'}</select><button class="primary" id="reduce" ${changed.length ? '' : 'disabled'}>Reduce this regression</button><div id="reduction-result">${reductionResult()}</div></div><div class="panel"><div class="experiment-head"><div class="experiment-icon blue">↶</div><div><h2>Counterfactual repair</h2><p>Which policy reverts restore declared behaviour?</p></div></div><p class="experiment-body">Test small sets of changed policy reverts against every declared intent and query. Preserve known decisions and remove new entrypoint → asset exposures under your pivot assumptions.</p><p class="help">Bounded search: up to 3 changed identities, 64 evaluations / 10 seconds. Proposals require human review.</p><button id="repair" class="primary">Find scoped repair proposals</button><div id="repair-result">${repairResult()}</div></div></div><div class="panel"><div class="section-line"><div class="experiment-head" style="margin-bottom:0"><div class="experiment-icon blue">⚗</div><div><h2>Fault-injection lab</h2><p>How sensitive is your intent suite to policy mistakes?</p></div></div><button id="mutate">Inject controlled policy faults</button></div><p class="help">Namespace+Pod AND → OR, wrong ports, removed allow rules, selector typos, and unrestricted rules. Use the clean baseline for a meaningful new-failure experiment. This measures intent sensitivity, not analyzer accuracy.</p><div id="mutation-result">${mutationResult()}</div></div>${robustnessPanel()}`;
}
function reductionResult() {
  const r = state.reduction;
  if (!r) return '';
  return `<div class="result-box"><span class="result-stat">${r.policy_units_before} → ${r.policy_units_after} <small>paired policy identities</small></span><p>${r.reduction_percent}% reduction · ${esc(r.status)} · ${r.calls} evaluations · ${r.duration_ms} ms</p><div class="alert info">Selected signature preserved in the static model. Runtime NOT VERIFIED.</div><p class="help">${esc(r.reason)} ${esc(r.scope)}</p><div class="code">${esc(JSON.stringify({ before: r.signature[0], after: r.signature[1], isolation: r.signature[2], candidate_intent_violations: r.signature[3], kept: r.kept }, null, 2))}</div><button id="download-bundle" class="small-button" style="margin-top:12px">↓ Download replay bundle</button></div>`;
}
function repairResult() {
  const r = state.repair;
  if (!r) return '';
  return `<div class="result-box"><p class="subtle">${r.calls} full-scope evaluations · ${r.duration_ms} ms · ${r.bounded ? 'budget reached' : 'smallest tested revert size'}</p>${r.solutions.length ? r.solutions.map((p, i) => `<div class="repair-card"><h3>Revert ${p.changed_objects} changed ${p.changed_objects === 1 ? 'policy' : 'policies'}</h3><p class="mono">${p.revert.map(esc).join('<br>')}</p><p>Intents pass; no Unknown decisions; no new conditional asset pairs beyond baseline. ${p.newly_reachable_vs_original_candidate.length} paths become reachable relative to the original candidate. Gate: ${esc(p.status)}.</p><div class="subnav-action"><button class="small-button" data-repair-open="${i}">Open as new review →</button><button class="small-button" data-repair-download="${i}">↓ Project JSON</button></div></div>`).join('') : '<div class="alert">No proposal satisfies the constraints within this search bound.</div>'}<p class="help">${esc(r.warning)}</p></div>`;
}
function mutationResult() {
  const r = state.mutation;
  if (!r) return '';
  return `<div class="result-box"><div class="metrics">${metric('INJECTED', r.total, 'Unique deterministic edits', 'cyan')}${metric('EFFECTIVE', r.effective_on_scope, 'Changed a declared decision', 'amber')}${metric('NEWLY CAUGHT', r.newly_caught, 'Introduced an intent failure', 'green')}${metric('INTENT GAPS', r.effective_on_scope - r.newly_caught, 'Effective faults without a new failure', 'red')}</div>${r.mutations.map((m, i) => `<div class="mutant"><div><strong>${esc(m.mutation)}</strong><small>${esc(m.policy)} · ${m.changed_tuples} affected queries · ${m.new_intent_failures.length} new intent failures</small></div>${pill(m.equivalent_on_scope ? 'EQUIVALENT' : m.caught_by_intents ? 'CAUGHT' : 'INTENT GAP')}<button class="small-button" data-mutant-open="${i}">Inspect →</button></div>`).join('')}</div>`;
}
function evidence() {
  const r = state.report,
    p = r.plan;
  return `<div class="section-line"><div><h2>Evidence, with its boundaries attached.</h2><div class="subtle">Static predictions and real network observations remain separate.</div></div>${pill('NOT_VERIFIED')}</div><div class="split"><div class="panel"><h2>Live verification plan</h2><div class="data-pair"><span>Required tuples per revision</span><strong>${p.count_per_phase} / 300 limit</strong></div><div class="data-pair"><span>Attempts per tuple</span><strong>3 fresh connections</strong></div><div class="data-pair"><span>Timeout / interval</span><strong>2 seconds / 1 second</strong></div><div class="data-pair"><span>Policy settle delay</span><strong>10 seconds (not a guarantee)</strong></div><div class="data-pair"><span>Unsupported plan tuples</span><strong>${p.unsupported.length}</strong></div><div class="data-pair"><span>Plan fingerprint</span><code>${p.hash.slice(0, 16)}…</code></div><p class="help">${esc(p.coverage_note)} IPv4 Pod-to-Pod TCP/UDP only. Templates, external IPs, SCTP, or privileged-port fixtures cannot receive complete live verification in this release.</p><div class="alert">A timeout is not proof of policy denial. Failed health controls or changed Pod/policy identity make results inconclusive.</div></div><div class="panel"><h2>Run a disposable lab</h2>${
    state.config.contexts.length
      ? `<p class="help">Only explicitly allowlisted context/server pairs can be used. This creates trusted fixtures and policies, then deletes only run-owned namespaces.</p><div class="field"><label for="context">Allowlisted context</label><select id="context">${state.config.contexts.map((c) => `<option>${esc(c)}</option>`).join('')}</select></div><button id="preview-plan">Preview exact mutations</button><div id="live-confirm"></div>`
      : `<p class="help">No live cluster is configured. Your review is fully usable in static mode; no runtime evidence is fabricated.</p><div class="code">make lab-up
# Bind the actual disposable context to its server:
export NETSCOPE_ALLOWED_CONTEXTS='{&quot;kind-netscope-lab&quot;:&quot;https://127.0.0.1:PORT&quot;}'
make serve</div><p class="help">See docs/LIVE_LAB.md. Docker, kind, kubectl, and an enforcing CNI are required on your machine.</p>`
  }<div id="job-result">${jobResult()}</div></div></div><div class="panel"><h2>Recorded static evidence</h2><div class="timeline"><div class="timeline-item"><small>${esc(formatDate(r.created_at))}</small>Input snapshot validated · SHA-256 ${r.input_hash.slice(0, 20)}…</div><div class="timeline-item">${r.stats.queries} queries evaluated under both revisions · ${r.stats.duration_ms} ms</div><div class="timeline-item">${r.intents.length} application intents checked independently of the change gate</div><div class="timeline-item">${r.stats.UNKNOWN} Unknown queries · ${r.plan.count_per_phase} required live tuples · runtime not verified</div></div><div class="subnav-action"><a class="text-link" href="/api/runs/${r.id}/report.json">↓ Full JSON evidence</a><a class="text-link" href="/api/runs/${r.id}/report.html">↓ Standalone HTML report</a></div></div>`;
}
function jobResult() {
  const j = state.job;
  if (!j) return '';
  const r = j.result || {};
  return `<div class="job-card"><div class="section-line"><h3>Live job ${j.id.slice(0, 8)}</h3>${pill(j.state)}</div>${r.error ? `<div class="alert">${esc(r.error)}</div>` : ''}<p>${r.observations?.length || 0} tuple/phase observations · exit ${r.exit_code ?? 'pending'}</p>${['QUEUED', 'RUNNING'].includes(j.state) ? '<button id="cancel-job" class="danger-button small-button">Cancel and clean owned resources</button>' : ''}<div class="timeline">${(
    r.events || []
  )
    .slice(-6)
    .map((e) => `<div class="timeline-item"><small>${esc(formatDate(e.at))}</small>${esc(e.message)}</div>`)
    .join(
      '',
    )}</div>${r.leftovers?.length ? `<div class="alert">${r.leftovers.length} cleanup leftovers. Inspect job JSON.</div>` : ''}${liveMatrix(r)}<button id="download-job" class="small-button">↓ Evidence JSON</button></div>`;
}
function inputs() {
  return `<div class="section-line"><div><h2>Inspectable inputs. Reproducible reviews.</h2><div class="subtle">Edit JSON or load a JSON/YAML project file. Imported images and commands are never executed.</div></div><button class="primary" id="run-editor">Run these inputs →</button></div><div class="split inputs-grid"><div class="panel"><div class="section-line"><h3>Project source</h3><input type="file" id="file-input" class="file-input" accept=".json,.yaml,.yml" aria-label="Load project file"></div><label class="sr-only" for="editor">Project YAML or JSON source</label><textarea id="editor" spellcheck="false">${esc(JSON.stringify(state.project, null, 2))}</textarea><div class="subnav-action" style="margin-top:13px"><button id="download-project" class="small-button">↓ Current project</button><span class="help">5 MiB / 30 endpoints / 17,400 query limit</span></div></div><div><div class="panel"><h2>Review history</h2><p class="help">Saved locally across restarts. Exact input fingerprints remain attached.</p>${state.history
    .slice(0, 12)
    .map(
      (h) =>
        `<div class="job-card"><div class="section-line"><strong style="font-size:11px">${esc(h.name)}</strong>${pill(h.status)}</div><p>${esc(formatDate(h.created))} · ${h.id.slice(0, 8)}</p><div class="subnav-action"><button class="small-button" data-open-run="${h.id}">Open</button><button class="small-button danger-button" data-delete-run="${h.id}">Delete</button></div></div>`,
    )
    .join(
      '',
    )}</div><div class="alert info">The finite query scope is explicit. Declared intents add their matching tuples automatically; Unknown and unsupported constructs prevent a complete pass.</div></div></div>`;
}
function traceHTML(d, phase) {
  if (!d) return '';
  let h = `<div class="trace"><div class="section-line"><h3>${phase}</h3>${pill(d.verdict)}</div><p>${esc(d.reason.replaceAll('-', ' '))}</p>`;
  for (const way of ['egress', 'ingress']) {
    const v = d[way];
    if (!v) continue;
    h += `<div class="trace-rows"><h3>${way === 'egress' ? '↑ Source egress' : '↓ Destination ingress'} ${pill(v.verdict)}</h3><span>${v.isolated ? 'Isolated: an explicit allow match is required.' : 'Unisolated: no selecting policy restricts this direction.'}</span>${v.selecting_policies.length ? `<span class="mono">Selected: ${v.selecting_policies.map(esc).join(', ')}</span>` : ''}${v.matched_rules.map((m) => `<div class="trace-rule"><strong>${esc(m.policy)}</strong> · ${way}[${m.rule_index}] · ${m.certain ? 'certain match' : 'unresolved peer'}<button class="link-button" style="display:block;margin-top:4px" data-policy="${esc(m.policy)}" data-policy-phase="${phase.toLowerCase()}">Inspect policy source ↗</button></div>`).join('')}${v.isolated && !v.matched_rules.length ? '<span class="error-text">No rule matches both peer and destination port/protocol.</span>' : ''}</div>`;
  }
  return h + '</div>';
}
let returnFocus = null;
function openDetail(tid) {
  returnFocus = document.activeElement;
  const r = state.report.rows.find((r) => r.tuple_id === tid);
  if (!r) return;
  state.selected = tid;
  const src = state.report.nodes.find((n) => n.id === r.source),
    dst = state.report.nodes.find((n) => n.id === r.destination);
  $('#drawer-content').innerHTML =
    `<h2 id="drawer-title">${esc(r.source)}<br><span class="muted">→</span> ${esc(r.destination)}</h2><div class="subnav-action"><span class="pill neutral">${r.protocol}/${r.port}</span>${delta(r.change)}</div><p class="help mono">${r.tuple_id}</p>${traceHTML(r.baseline_decision, 'Baseline')}${traceHTML(r.candidate_decision, 'Candidate')}<h3 style="margin-top:20px">Endpoint evidence</h3><div class="code">${esc(JSON.stringify({ source: { labels: src?.labels }, destination: { labels: dst?.labels, declared_ports: dst?.ports } }, null, 2))}</div><p class="help">Named ports are resolved against destination declarations. External IP rules evaluate only the Pod-controlled direction. Static model only.</p>${['NEWLY_ALLOWED', 'NEWLY_BLOCKED'].includes(r.change) ? `<button id="drawer-reduce" class="primary">Reduce this regression →</button>` : ''}<div id="policy-source"></div>`;
  $('#drawer-backdrop').hidden = false;
  $('#drawer').hidden = false;
  $('#close-drawer').focus();
  bindDrawer();
}
function closeDrawer() {
  $('#drawer').hidden = true;
  $('#drawer-backdrop').hidden = true;
  if (returnFocus?.isConnected) returnFocus.focus();
}
function bindDrawer() {
  $$('[data-policy]').forEach(
    (b) =>
      (b.onclick = () => {
        let policies = state.project[b.dataset.policyPhase];
        if (typeof policies === 'string') {
          toast('Policy YAML is available in Inputs.');
          return;
        }
        const p = policies.find((p) => `${p.metadata?.namespace}/${p.metadata?.name}` === b.dataset.policy);
        $('#policy-source').innerHTML =
          `<h3 style="margin-top:17px">${esc(b.dataset.policy)}</h3><div class="code">${esc(JSON.stringify(p, null, 2))}</div>`;
      }),
  );
  $('#drawer-reduce')?.addEventListener('click', () => {
    closeDrawer();
    goto('experiments');
    $('#witness').value = state.selected;
    $('#reduce').click();
  });
}
function download(content, filename, type = 'application/json') {
  const blob = new Blob(
    [
      typeof content === 'string' || content instanceof ArrayBuffer || ArrayBuffer.isView(content)
        ? content
        : JSON.stringify(content, null, 2),
    ],
    { type },
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
async function loadExample(id) {
  const raw = await api('/api/examples/' + id);
  $('#scenario').value = id;
  await runProject(raw);
}
function bindView() {
  $$('[data-goto]').forEach((b) => (b.onclick = () => goto(b.dataset.goto)));
  $$('[data-load]').forEach((b) => (b.onclick = () => task(b, () => loadExample(b.dataset.load))));
  $$('[data-phase]').forEach(
    (b) =>
      (b.onclick = () => {
        state.phase = b.dataset.phase;
        render();
      }),
  );
  $$('[data-row]').forEach((b) => {
    b.onclick = () => openDetail(b.dataset.row);
    b.onkeydown = (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openDetail(b.dataset.row);
      }
    };
  });
  $$('[data-node]').forEach((b) => {
    const fn = () => {
      state.filter.text = b.dataset.node;
      state.filter.change = 'ALL';
      goto('connections');
    };
    b.onclick = fn;
    b.onkeydown = (e) => {
      if (e.key === 'Enter') fn();
    };
  });
  if ($('#search')) {
    $('#search').oninput = (e) => {
      state.filter.text = e.target.value;
      state.limit = 60;
      refreshRows();
    };
    $('#change-filter').onchange = (e) => {
      state.filter.change = e.target.value;
      state.limit = 60;
      refreshRows();
    };
    $('#verdict-filter').onchange = (e) => {
      state.filter.verdict = e.target.value;
      state.limit = 60;
      refreshRows();
    };
    $('#more-rows').onclick = () => {
      state.limit += 60;
      refreshRows();
    };
  }
  $('#no-pivots')?.addEventListener('click', (e) =>
    task(e.target, async () => {
      const p = structuredClone(state.project);
      p.threatModel.pivots = [];
      p.name += ' · no relay assumption';
      await runProject(p);
    }),
  );
  $$('[data-remove-pivot]').forEach(
    (b) =>
      (b.onclick = () =>
        task(b, async () => {
          const p = structuredClone(state.project);
          p.threatModel.pivots = p.threatModel.pivots.filter((pivot) => pivot !== b.dataset.removePivot);
          p.name += ' · one relay removed';
          await runProject(p);
        })),
  );
  $('#reduce')?.addEventListener('click', (e) =>
    task(e.target, async () => {
      state.reduction = await api(`/api/runs/${state.report.id}/reduce`, {
        method: 'POST',
        body: JSON.stringify({ tuple_id: $('#witness').value }),
      });
      render();
    }),
  );
  $('#download-bundle')?.addEventListener('click', (e) =>
    task(e.target, async () => {
      const r = await fetch(`/api/runs/${state.report.id}/bundle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-NetScope-Token': state.config.token },
        body: JSON.stringify({ tuple_id: state.reduction.witness }),
      });
      if (!r.ok) throw new Error((await r.json()).detail);
      const blob = await r.blob();
      download(await blob.arrayBuffer(), 'netscope-replay.zip', 'application/zip');
    }),
  );
  $('#repair')?.addEventListener('click', (e) =>
    task(e.target, async () => {
      state.repair = await api(`/api/runs/${state.report.id}/repair`, { method: 'POST', body: '{}' });
      render();
    }),
  );
  $$('[data-repair-open]').forEach(
    (b) =>
      (b.onclick = () => task(b, () => runProject(state.repair.solutions[+b.dataset.repairOpen].project))),
  );
  $$('[data-repair-download]').forEach(
    (b) =>
      (b.onclick = () =>
        download(state.repair.solutions[+b.dataset.repairDownload].project, 'netscope-repair-project.json')),
  );
  $('#mutate')?.addEventListener('click', (e) =>
    task(e.target, async () => {
      state.mutation = await api(`/api/runs/${state.report.id}/mutate`, { method: 'POST', body: '{}' });
      render();
    }),
  );
  $$('[data-mutant-open]').forEach(
    (b) =>
      (b.onclick = () => task(b, () => runProject(state.mutation.mutations[+b.dataset.mutantOpen].project))),
  );
  $('#run-editor')?.addEventListener('click', (e) =>
    task(e.target, async () => {
      const content = $('#editor').value;
      const r = await api('/api/runs', { method: 'POST', body: JSON.stringify({ project: content }) });
      state.report = r;
      state.project = await api(`/api/runs/${r.id}/project`);
      state.history = await api('/api/runs');
      state.reduction = state.repair = state.mutation = null;
      goto('overview');
      toast('Review saved from edited inputs');
    }),
  );
  $('#file-input')?.addEventListener('change', async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    if (f.size > 5 * 1024 * 1024) {
      notice('Input exceeds 5 MiB');
      return;
    }
    $('#editor').value = await f.text();
    toast('File loaded. Run these inputs to validate and review.');
  });
  $('#download-project')?.addEventListener('click', () => download(state.project, 'netscope-project.json'));
  $$('[data-open-run]').forEach((b) => (b.onclick = () => task(b, () => openRun(b.dataset.openRun))));
  $$('[data-delete-run]').forEach(
    (b) =>
      (b.onclick = () => {
        if (confirm('Delete this saved review and its local evidence?'))
          task(b, async () => {
            await api('/api/runs/' + b.dataset.deleteRun, { method: 'DELETE' });
            state.history = await api('/api/runs');
            if (b.dataset.deleteRun === state.report.id) {
              if (state.history.length) await openRun(state.history[0].id);
              else await loadExample('agent-escape');
              return;
            }
            render();
          });
      }),
  );
  $('#preview-plan')?.addEventListener('click', (e) =>
    task(e.target, async () => {
      const context = $('#context').value;
      const p = await api(`/api/runs/${state.report.id}/plan`, {
        method: 'POST',
        body: JSON.stringify({ context }),
      });
      $('#live-confirm').innerHTML =
        `<div class="alert info" style="margin-top:14px">${esc(p.context)} → ${esc(p.server)}<br>${p.plan.count_per_phase} tuples per phase. ${p.mutations.map(esc).join(' · ')}</div><div class="field"><label for="confirm-live">Type RUN DISPOSABLE LAB</label><input id="confirm-live" autocomplete="off"></div><button class="danger-button" id="start-live">Run exact confirmed plan</button>`;
      $('#start-live').onclick = (e) =>
        task(e.target, async () => {
          const j = await api(`/api/runs/${state.report.id}/verify`, {
            method: 'POST',
            body: JSON.stringify({ context, plan_hash: p.plan.hash, confirm: $('#confirm-live').value }),
          });
          state.job = await api('/api/jobs/' + j.job_id);
          render();
          pollJob(j.job_id);
        });
    }),
  );
  $('#cancel-job')?.addEventListener('click', (e) =>
    task(e.target, async () => {
      await api(`/api/jobs/${state.job.id}/cancel`, { method: 'POST', body: '{}' });
      toast('Cancellation requested; cleanup will retain diagnostics.');
    }),
  );
  $('#download-job')?.addEventListener('click', () => download(state.job, 'netscope-live-evidence.json'));
}
function refreshRows() {
  const rows = filteredRows();
  $('#connections-body').innerHTML = connectionRows(rows);
  $('#row-count').textContent =
    `Showing ${Math.min(state.limit, rows.length)} of ${rows.length} matching queries`;
  $('#more-rows').hidden = state.limit >= rows.length;
  $$('[data-row]').forEach((b) => {
    b.onclick = () => openDetail(b.dataset.row);
    b.onkeydown = (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openDetail(b.dataset.row);
      }
    };
  });
}
async function pollJob(id) {
  try {
    state.job = await api('/api/jobs/' + id);
    if (state.view === 'evidence') {
      const result = $('#job-result');
      if (result) {
        result.innerHTML = jobResult();
        bindView();
        bindExtraExperiments();
      }
    }
    if (['QUEUED', 'RUNNING'].includes(state.job.state)) setTimeout(() => pollJob(id), 1600);
  } catch (e) {
    notice(e);
  }
}
$('#nav').addEventListener('click', (e) => {
  const b = e.target.closest('[data-view]');
  if (b) goto(b.dataset.view);
});
$('#run-review').onclick = (e) => task(e.target, () => loadExample($('#scenario').value));
$('#scenario').onchange = () => {
  toast('Scenario selected. Run review to analyze it.');
};
$('#close-drawer').onclick = closeDrawer;
$('#drawer-backdrop').onclick = closeDrawer;
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeDrawer();
  if (e.key === 'Tab' && !$('#drawer').hidden) {
    const targets = $$('#drawer button, #drawer a, #drawer [tabindex="0"]');
    const first = targets[0],
      last = targets.at(-1);
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last?.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first?.focus();
    }
  }
});
window.addEventListener('hashchange', () => {
  const v = location.hash.slice(1);
  if (names[v] && v !== state.view) {
    state.view = v;
    render();
  }
});
(async () => {
  try {
    state.config = await api('/api/config');
    $('#version').textContent = 'v' + state.config.version;
    const examples = await api('/api/examples');
    $('#scenario').innerHTML = examples
      .map((x) => `<option value="${x.id}">${esc(x.name)}</option>`)
      .join('');
    state.view = names[location.hash.slice(1)] ? location.hash.slice(1) : 'overview';
    state.history = await api('/api/runs');
    const saved = lastRun();
    const previous = state.history.find((r) => r.id === saved) || state.history[0];
    if (previous) await openRun(previous.id);
    else await loadExample('agent-escape');
  } catch (e) {
    notice(e);
    $('#view-container').innerHTML =
      '<div class="empty-state"><h2>The lab could not initialize.</h2><p>Check the error above and the server terminal.</p></div>';
  }
})();
