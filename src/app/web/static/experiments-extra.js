'use strict';

function endpointOptions(selected) {
  return state.report.nodes
    .map((n) => `<option value="${esc(n.id)}" ${n.id === selected ? 'selected' : ''}>${esc(n.id)}</option>`)
    .join('');
}

function robustnessPanel() {
  const selected = state.labelEndpoint || state.report.threat.entrypoints[0] || state.report.nodes[0]?.id;
  const node = state.report.nodes.find((n) => n.id === selected);
  return `<div class="experiment-grid"><div class="panel"><h2>Find missing regression checks</h2><p class="help">Use a passing reference candidate. Draft exact connection checks from faults missed by its intents. Selection uses training faults; a separate synthetic holdout measures transfer.</p><button class="primary" id="suggest-checks">Suggest missing checks</button><div id="coverage-result">${coverageResult()}</div></div><div class="panel"><h2>What if a workload label changes?</h2><p class="help">Change one Pod's labels in an immutable scenario. Inspect policy selection, changed permissions, new asset pairs, and intents that lose their matches. This does not establish permission to alter labels.</p><label class="field" for="label-endpoint">Workload<select id="label-endpoint">${endpointOptions(selected)}</select></label><label class="field" for="label-editor">Full replacement labels (JSON)<textarea id="label-editor" rows="5">${esc(JSON.stringify(node?.labels || {}, null, 2))}</textarea></label><div class="subnav-action"><button class="small-button" id="drop-app-label">Remove app label</button><button class="small-button" id="trusted-label">Set app=payments (demo)</button></div><button class="primary" id="run-labels">Analyze label counterfactual</button><div id="label-result">${labelResult()}</div></div></div>`;
}

function coverageResult() {
  const r = state.coverage;
  if (!r) return '';
  return `<div class="result-box"><h3>${r.draft_count} draft checks · ${r.faults_generated} generated faults</h3><div class="table-wrap"><table><thead><tr><th>Split</th><th>Effective faults</th><th>Intents detect</th><th>With drafts</th></tr></thead><tbody>${['training', 'holdout'].map((split) => `<tr><td>${esc(split)}</td><td>${r[split].effective_faults}</td><td>${r[split].caught_before}</td><td>${r[split].caught_with_drafts}</td></tr>`).join('')}</tbody></table></div><p class="help">${r.budget_limited ? 'Time budget reached; this is a partial fault suite.' : 'Holdout faults were excluded from check selection.'} ${esc(r.warning)}</p>${r.specification.checks.map((c) => `<div class="draft-check"><strong>${esc(c.source)} → ${esc(c.destination)}</strong><small>${esc(c.protocol)}/${c.port} · ${esc(c.expect)}</small></div>`).join('')}<div class="subnav-action"><button class="small-button" id="download-checks" ${r.draft_count ? '' : 'disabled'}>↓ Checks JSON</button><button class="small-button" id="verify-drafts" ${r.draft_count ? '' : 'disabled'}>Verify on reference</button></div>${state.draftCheckResult ? `<p>Draft verification: ${pill(state.draftCheckResult.status)} · ${state.draftCheckResult.checks.length} exact candidate checks</p>` : ''}<p class="help">CLI: netscope check project.json draft-checks.json. A passing check suite is separate from the full review gate.</p></div>`;
}

function labelResult() {
  const r = state.labelResult;
  if (!r) return '';
  const invalid = r.intents.filter((i) => i.candidate.status !== 'PASS');
  return `<div class="result-box"><h3>${r.changes.length} changed permissions · ${r.new_asset_paths.length} new asset pairs · ${r.shortened_asset_paths.length} shorter asset paths</h3>${r.shortened_asset_paths.map((p) => `<p class="help"><strong>${esc(p.after.entrypoint)} → ${esc(p.after.asset)}</strong>: ${p.before.hops.length} hops → ${p.after.hops.length} hop(s). ${esc(p.after.kind)} under the stated compromise assumption.</p>`).join('')}${['egress', 'ingress'].map((d) => `<div class="sensitivity-check"><strong>${esc(d)} policy selection</strong><p>Before: ${r.targeting[d].before.isolated === null ? 'not queried' : r.targeting[d].before.isolated ? 'isolated' : 'unisolated'} · ${esc(r.targeting[d].before.policies.join(', ') || 'no selecting policy')}<br>After: ${r.targeting[d].after.isolated === null ? 'not queried' : r.targeting[d].after.isolated ? 'isolated' : 'unisolated'} · ${esc(r.targeting[d].after.policies.join(', ') || 'no selecting policy')}</p></div>`).join('')}<p class="help">${invalid.length} candidate intents are failing, invalid, or unknown. ${r.additional_intent_queries} additional intent queries are outside the shared ${r.shared_queries}-query comparison.</p>${invalid.map((i) => `<div class="draft-check"><strong>${esc(i.intent_id)}</strong><small>${esc(i.candidate.status)} · ${i.matched_count} matches · ${esc(i.problems.join(', '))}</small></div>`).join('')}<div class="table-wrap"><table><thead><tr><th>Connection</th><th>Port</th><th>Reference → edited</th></tr></thead><tbody>${r.changes
    .slice(0, 8)
    .map(
      (c) =>
        `<tr><td>${esc(c.source)} → ${esc(c.destination)}</td><td>${esc(c.protocol)}/${c.port}</td><td>${pill(c.before)} → ${pill(c.after)}</td></tr>`,
    )
    .join(
      '',
    )}</tbody></table></div><p class="help">Showing ${Math.min(8, r.changes.length)} of ${r.changes.length} changes. ${esc(r.scope)} ${esc(r.warning)}</p><div class="subnav-action"><button class="small-button" id="open-label-review">Open edited scenario as new review →</button><button class="small-button" id="download-label-result">↓ Full comparison JSON</button></div></div>`;
}

function queryComposer() {
  const q = state.queryResult
    ? state.querySpecification.checks[0]
    : {
        source: state.report.nodes[0]?.id,
        destination: state.report.nodes[1]?.id,
        protocol: 'TCP',
        port: 8080,
        expect: 'must_allow',
      };
  return `<details class="panel query-composer"><summary>Ask about another connection</summary><p class="help">Evaluate an exact candidate query, including ports outside the saved table. This is a separate static check and does not expand the saved review or its live coverage.</p><div class="query-fields"><label>Source<select id="ask-source">${endpointOptions(q.source)}</select></label><label>Destination<select id="ask-destination">${endpointOptions(q.destination)}</select></label><label>Protocol<select id="ask-protocol">${['TCP', 'UDP', 'SCTP'].map((p) => `<option ${p === q.protocol ? 'selected' : ''}>${p}</option>`).join('')}</select></label><label>Port<input id="ask-port" type="number" min="1" max="65535" value="${q.port}"></label><label>Expected<select id="ask-expect"><option value="must_allow" ${q.expect === 'must_allow' ? 'selected' : ''}>Allow</option><option value="must_deny" ${q.expect === 'must_deny' ? 'selected' : ''}>Deny</option></select></label></div><button class="primary" id="ask-query">Evaluate connection check</button>${state.queryResult ? `<div class="result-box">${pill(state.queryResult.status)}<p>${esc(state.queryResult.checks[0].source)} → ${esc(state.queryResult.checks[0].destination)} · ${esc(state.queryResult.checks[0].protocol)}/${state.queryResult.checks[0].port} · model ${pill(state.queryResult.checks[0].actual)}</p><button class="small-button" id="download-query-check">↓ Save this regression check</button></div>` : ''}</details>`;
}

function liveMatrix(r) {
  const c = r.coverage;
  if (!c)
    return '<p class="help">Per-connection coverage is available after this worker records observations.</p>';
  return `<div class="result-box"><h3>Model versus recorded observations</h3><p>${c.conclusive_both_revisions} / ${c.planned_connections} planned connections conclusive in both revisions · ${c.model_queries} statically analyzed</p><p class="help">Conclusive placement: ${c.cross_node_conclusive} cross-node · ${c.same_node_conclusive} same-node · ${c.unknown_placement_conclusive} unknown. Protocols observed: ${esc(c.protocols_observed.join(', ') || 'none')}.</p><div class="table-wrap"><table><thead><tr><th>Connection</th><th>Baseline: model / observed</th><th>Candidate: model / observed</th><th>Node placement</th></tr></thead><tbody>${c.matrix.map((row) => `<tr><td>${esc(row.source)} → ${esc(row.destination)}<small>${esc(row.protocol)}/${row.port}</small></td>${['baseline', 'candidate'].map((phase) => `<td>${pill(row[phase].model)}<br>${pill(row[phase].verdict)}<small>${row[phase].mismatch ? 'MISMATCH' : row[phase].complete ? 'Conclusive' : 'Incomplete / not tested'} · ${row[phase].successful_attempts}/${row[phase].attempts} successful attempts</small></td>`).join('')}<td>${esc(row.placement)}<small>${esc(row.source_node || '?')} → ${esc(row.destination_node || '?')}</small></td></tr>`).join('')}</tbody></table></div><p class="help">${esc(c.note)}</p></div>`;
}

function bindExtraExperiments() {
  const bind = (selector, event, callback) => {
    const element = $(selector);
    if (element) element['on' + event] = callback;
  };
  bind('#suggest-checks', 'click', (e) =>
    task(e.target, async () => {
      state.coverage = await api(`/api/runs/${state.report.id}/checks/suggest`, { method: 'POST' });
      state.draftCheckResult = null;
      render();
    }),
  );
  bind('#download-checks', 'click', () => download(state.coverage.specification, 'draft-checks.json'));
  bind('#verify-drafts', 'click', (e) =>
    task(e.target, async () => {
      state.draftCheckResult = await api(`/api/runs/${state.report.id}/checks/verify`, {
        method: 'POST',
        body: JSON.stringify(state.coverage.specification),
      });
      render();
    }),
  );
  bind('#label-endpoint', 'change', (e) => {
    state.labelEndpoint = e.target.value;
    state.labelResult = null;
    $('#label-result').innerHTML = '';
    $('#label-editor').value = JSON.stringify(
      state.report.nodes.find((n) => n.id === e.target.value).labels,
      null,
      2,
    );
  });
  bind('#drop-app-label', 'click', (e) =>
    task(e.target, async () => {
      const labels = JSON.parse($('#label-editor').value);
      delete labels.app;
      $('#label-editor').value = JSON.stringify(labels, null, 2);
    }),
  );
  bind('#trusted-label', 'click', (e) =>
    task(e.target, async () => {
      const labels = JSON.parse($('#label-editor').value);
      labels.app = 'payments';
      $('#label-editor').value = JSON.stringify(labels, null, 2);
    }),
  );
  bind('#run-labels', 'click', (e) =>
    task(e.target, async () => {
      state.labelEndpoint = $('#label-endpoint').value;
      state.labelResult = await api(`/api/runs/${state.report.id}/labels`, {
        method: 'POST',
        body: JSON.stringify({ endpoint: state.labelEndpoint, labels: JSON.parse($('#label-editor').value) }),
      });
      render();
    }),
  );
  bind('#open-label-review', 'click', (e) => task(e.target, () => runProject(state.labelResult.project)));
  bind('#download-label-result', 'click', () => download(state.labelResult, 'label-experiment.json'));
  bind('#ask-query', 'click', (e) =>
    task(e.target, async () => {
      const spec = {
        schemaVersion: 1,
        checks: [
          {
            id: 'manual-query',
            source: $('#ask-source').value,
            destination: $('#ask-destination').value,
            protocol: $('#ask-protocol').value,
            port: Number($('#ask-port').value),
            expect: $('#ask-expect').value,
          },
        ],
      };
      state.queryResult = await api(`/api/runs/${state.report.id}/checks/verify`, {
        method: 'POST',
        body: JSON.stringify(spec),
      });
      state.querySpecification = spec;
      render();
      $('.query-composer').open = true;
    }),
  );
  bind('#download-query-check', 'click', () => download(state.querySpecification, 'connection-check.json'));
}
