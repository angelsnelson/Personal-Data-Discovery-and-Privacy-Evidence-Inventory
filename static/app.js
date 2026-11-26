const ALL_CLASSES = [
  "DIRECT_IDENTIFIER",
  "NATIONAL_ID",
  "FINANCIAL_INFO",
  "CONTACT_LOCATION",
  "SENSITIVE_ATTRIBUTE",
  "NONE",
];

let appState = null;
let activeView = "inventory";
let activeSubtab = "sub-sources";
let selectedClassFilter = "ALL";
let inspectedFieldKey = null;
let showRawSamplesInDrawer = false;
let draftRules = [];
let toastTimer = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showToast(message) {
  const el = document.getElementById("status-toast");
  el.textContent = message;
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.add("hidden");
  }, 3400);
}

async function apiRequest(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) detail = errJson.detail;
    } catch {
      // ignore parse failure
    }
    throw new Error(detail);
  }
  return res.json();
}

function formatPct(val) {
  return `${(Number(val || 0) * 100).toFixed(1)}%`;
}

function classTagHtml(cls) {
  if (cls === "NONE") {
    return `<span class="tag tag-muted">NONE</span>`;
  }
  if (cls === "SENSITIVE_ATTRIBUTE" || cls === "NATIONAL_ID") {
    return `<span class="tag tag-ink">${escapeHtml(cls)}</span>`;
  }
  return `<span class="tag">${escapeHtml(cls)}</span>`;
}

function gapTagHtml(gapStatus) {
  if (gapStatus === "COMPLETE") {
    return `<span class="tag">COMPLETE</span>`;
  }
  if (gapStatus === "NOT_APPLICABLE") {
    return `<span class="tag tag-muted">N/A (NON-PII)</span>`;
  }
  return `<span class="tag tag-accent">${escapeHtml(gapStatus)}</span>`;
}

function switchView(viewId) {
  activeView = viewId;
  document.querySelectorAll(".nav-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === viewId);
  });
  document.querySelectorAll(".view-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `view-${viewId}`);
  });
}

function switchSubtab(subtabId) {
  activeSubtab = subtabId;
  document.querySelectorAll(".subtab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.subtab === subtabId);
  });
  document.querySelectorAll(".subtab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === subtabId);
  });
}

function renderAll() {
  if (!appState) return;
  const { summary, evaluation, generated_at } = appState;

  document.getElementById("last-scan-time").textContent = new Date(generated_at).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  document.getElementById("nav-gap-badge").textContent = String(summary.gap_count);

  renderInventoryView();
  renderGapsView();
  renderEvaluationView();
  renderSourcesAndRulesView();
  renderScopeView();

  if (inspectedFieldKey) {
    const found = appState.inventory.find((r) => r.field_key === inspectedFieldKey);
    if (found) {
      renderDrawer(found);
    } else {
      closeDrawer();
    }
  }
}

/* ---------------- VIEW 1: EVIDENCE INVENTORY ---------------- */
function renderInventoryView() {
  const { summary, evaluation, inventory } = appState;

  document.getElementById("inventory-kpis").innerHTML = `
    <div class="kpi-cell">
      <span class="label-xs">TOTAL FIELDS SCANNED</span>
      <span class="kpi-value tabular-nums">${summary.total_fields}</span>
      <span class="kpi-sub">${summary.csv_sources} CSV files &bull; ${summary.sql_tables} SQLite tables</span>
    </div>
    <div class="kpi-cell">
      <span class="label-xs">CANDIDATE PII FIELDS</span>
      <span class="kpi-value tabular-nums">${summary.candidate_pii_fields}</span>
      <span class="kpi-sub">${summary.non_pii_fields} operational NONE fields</span>
    </div>
    <div class="kpi-cell">
      <span class="label-xs">EVIDENCE GAPS FLAGGED</span>
      <span class="kpi-value accent tabular-nums">${summary.gap_count}</span>
      <span class="kpi-sub">${summary.missing_both_count} missing both purpose &amp; retention</span>
    </div>
    <div class="kpi-cell">
      <span class="label-xs">BENCHMARK MACRO F1</span>
      <span class="kpi-value tabular-nums">${formatPct(evaluation.macro_f1)}</span>
      <span class="kpi-sub">P: ${formatPct(evaluation.macro_precision)} &bull; R: ${formatPct(evaluation.macro_recall)}</span>
    </div>
  `;

  const stripEl = document.getElementById("class-filter-strip");
  stripEl.innerHTML = ALL_CLASSES.map((cls) => {
    const count = summary.class_counts[cls] || 0;
    const isActive = selectedClassFilter === cls;
    return `
      <button class="class-pill ${isActive ? "active" : ""}" data-cls="${cls}" type="button">
        <span class="class-pill-name">${cls}</span>
        <span class="class-pill-count tabular-nums">${count}</span>
      </button>
    `;
  }).join("");

  stripEl.querySelectorAll(".class-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      selectedClassFilter = selectedClassFilter === pill.dataset.cls ? "ALL" : pill.dataset.cls;
      renderInventoryView();
    });
  });

  const searchVal = document.getElementById("inv-search").value.trim().toLowerCase();
  const srcFilter = document.getElementById("inv-source-filter").value;
  const gapFilter = document.getElementById("inv-gap-filter").value;

  const filtered = inventory.filter((rec) => {
    if (selectedClassFilter !== "ALL" && rec.predicted_class !== selectedClassFilter) return false;
    if (srcFilter !== "ALL" && rec.source_type !== srcFilter) return false;
    if (gapFilter === "ANY_GAP") {
      if (!rec.is_candidate_pii || rec.gap_status === "COMPLETE") return false;
    } else if (gapFilter !== "ALL" && rec.gap_status !== gapFilter) {
      return false;
    }
    if (searchVal) {
      const hay = [
        rec.container,
        rec.column,
        rec.predicted_class,
        rec.declared_purpose,
        rec.retention_schedule,
        rec.gap_status,
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(searchVal)) return false;
    }
    return true;
  });

  const tbody = document.getElementById("inventory-tbody");
  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="9" class="body-muted">No inventory fields match the active filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered
    .map((rec) => {
      const isGap = rec.is_candidate_pii && rec.gap_status !== "COMPLETE";
      const confPct = Math.round(rec.confidence * 100);
      return `
        <tr class="${isGap ? "row-gap" : ""}">
          <td><span class="tag ${rec.source_type === "SQL" ? "tag-ink" : ""}">${escapeHtml(rec.source_type)}</span></td>
          <td>
            <div class="field-title">${escapeHtml(rec.column)}</div>
            <div class="field-container">${escapeHtml(rec.container)} &bull; ${rec.row_count} rows</div>
          </td>
          <td>${classTagHtml(rec.predicted_class)}</td>
          <td>
            <div class="conf-bar-wrap tabular-nums">
              <div class="conf-bar"><div class="conf-fill ${rec.confidence >= 0.7 ? "high" : ""}" style="width:${confPct}%"></div></div>
              <span>${rec.confidence.toFixed(2)}</span>
            </div>
          </td>
          <td><span class="sample-code">${escapeHtml(rec.masked_samples.slice(0, 2).join(" | ") || "—")}</span></td>
          <td>${rec.declared_purpose ? escapeHtml(rec.declared_purpose) : `<span class="tag tag-warn">UNDECLARED</span>`}</td>
          <td>${rec.retention_schedule ? escapeHtml(rec.retention_schedule) : `<span class="tag tag-warn">UNDECLARED</span>`}</td>
          <td>${gapTagHtml(rec.gap_status)}</td>
          <td>
            <button class="btn btn-sm btn-outline btn-inspect" data-key="${escapeHtml(rec.field_key)}" type="button">INSPECT</button>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll(".btn-inspect").forEach((btn) => {
    btn.addEventListener("click", () => {
      const rec = appState.inventory.find((r) => r.field_key === btn.dataset.key);
      if (rec) openDrawer(rec);
    });
  });
}

/* ---------------- VIEW 2: METADATA & GAP REPORT ---------------- */
function renderGapsView() {
  const { summary, inventory } = appState;
  const piiFields = inventory.filter((r) => r.is_candidate_pii);
  const completeCount = piiFields.filter((r) => r.gap_status === "COMPLETE").length;
  const coverage = piiFields.length ? (completeCount / piiFields.length) * 100 : 100;

  document.getElementById("gaps-kpis").innerHTML = `
    <div class="kpi-cell">
      <span class="label-xs">CANDIDATE PII WITH GAPS</span>
      <span class="kpi-value accent tabular-nums">${summary.gap_count}</span>
      <span class="kpi-sub">Out of ${piiFields.length} candidate PII fields</span>
    </div>
    <div class="kpi-cell">
      <span class="label-xs">MISSING BOTH FIELDS</span>
      <span class="kpi-value accent tabular-nums">${summary.missing_both_count}</span>
      <span class="kpi-sub">No purpose &amp; no retention</span>
    </div>
    <div class="kpi-cell">
      <span class="label-xs">SINGLE-FIELD GAPS</span>
      <span class="kpi-value tabular-nums">${summary.missing_purpose_count + summary.missing_retention_count}</span>
      <span class="kpi-sub">${summary.missing_purpose_count} purpose &bull; ${summary.missing_retention_count} retention</span>
    </div>
    <div class="kpi-cell">
      <span class="label-xs">REGISTRY COMPLETENESS</span>
      <span class="kpi-value tabular-nums">${coverage.toFixed(1)}%</span>
      <span class="kpi-sub">${completeCount} candidate PII fields documented</span>
    </div>
  `;

  const filterMode = document.getElementById("gap-view-filter").value;
  const rows = piiFields.filter((r) => {
    if (filterMode === "ALL_GAPS") return r.gap_status !== "COMPLETE";
    if (filterMode === "ALL_PII") return true;
    return r.gap_status === filterMode;
  });

  const tbody = document.getElementById("gaps-tbody");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="body-muted">No metadata gaps matching this filter. All selected candidate PII fields have documented purpose and retention schedules.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows
    .map(
      (r) => `
      <tr class="${r.gap_status !== "COMPLETE" ? "row-gap" : ""}" data-gap-key="${escapeHtml(r.field_key)}">
        <td>
          <div class="field-title">${escapeHtml(r.column)}</div>
          <div class="field-container">[${escapeHtml(r.source_type)}] ${escapeHtml(r.container)}</div>
        </td>
        <td>${classTagHtml(r.predicted_class)}</td>
        <td>${gapTagHtml(r.gap_status)}</td>
        <td>
          <input class="inline-edit-input js-gap-purpose" type="text" value="${escapeHtml(r.declared_purpose)}" placeholder="Enter business purpose..." />
        </td>
        <td>
          <input class="inline-edit-input js-gap-retention" type="text" value="${escapeHtml(r.retention_schedule)}" placeholder="e.g. 5 years post closure" />
        </td>
        <td>
          <input class="inline-edit-input js-gap-owner" type="text" value="${escapeHtml(r.owner_team)}" placeholder="Owner team" />
        </td>
        <td>
          <button class="btn btn-sm btn-ink js-save-gap" type="button">SAVE</button>
        </td>
      </tr>
    `
    )
    .join("");

  tbody.querySelectorAll(".js-save-gap").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const tr = btn.closest("tr");
      const fieldKey = tr.dataset.gapKey;
      const rec = appState.inventory.find((x) => x.field_key === fieldKey);
      if (!rec) return;

      const payload = {
        field_key: rec.field_key,
        source_type: rec.source_type,
        container: rec.container,
        column: rec.column,
        declared_purpose: tr.querySelector(".js-gap-purpose").value.trim(),
        retention_schedule: tr.querySelector(".js-gap-retention").value.trim(),
        owner_team: tr.querySelector(".js-gap-owner").value.trim(),
      };
      try {
        appState = await apiRequest("/api/metadata", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        renderAll();
        showToast(`Saved metadata for ${rec.container}.${rec.column}`);
      } catch (err) {
        showToast(`Error: ${err.message}`);
      }
    });
  });
}

/* ---------------- VIEW 3: PRECISION & RECALL LAB ---------------- */
function renderEvaluationView() {
  const ev = appState.evaluation;

  document.getElementById("eval-kpis").innerHTML = `
    <div class="kpi-cell">
      <span class="label-xs">MACRO PRECISION (5 PII)</span>
      <span class="kpi-value tabular-nums">${formatPct(ev.macro_precision)}</span>
      <span class="kpi-sub">Micro P: ${formatPct(ev.micro_precision)}</span>
    </div>
    <div class="kpi-cell">
      <span class="label-xs">MACRO RECALL (5 PII)</span>
      <span class="kpi-value tabular-nums">${formatPct(ev.macro_recall)}</span>
      <span class="kpi-sub">Micro R: ${formatPct(ev.micro_recall)}</span>
    </div>
    <div class="kpi-cell">
      <span class="label-xs">MACRO F1 SCORE</span>
      <span class="kpi-value accent tabular-nums">${formatPct(ev.macro_f1)}</span>
      <span class="kpi-sub">Micro F1: ${formatPct(ev.micro_f1)}</span>
    </div>
    <div class="kpi-cell">
      <span class="label-xs">EXACT-MATCH ACCURACY</span>
      <span class="kpi-value tabular-nums">${formatPct(ev.overall_accuracy)}</span>
      <span class="kpi-sub">${ev.exact_match_count}/${ev.evaluated_field_count} labelled (${ev.unlabelled_field_count} unlabelled)</span>
    </div>
  `;

  document.getElementById("eval-class-tbody").innerHTML = ev.per_class
    .map((m) => {
      const pPct = Math.round(m.precision * 100);
      const rPct = Math.round(m.recall * 100);
      const fPct = Math.round(m.f1 * 100);
      return `
        <tr>
          <td>${classTagHtml(m.data_class)}</td>
          <td class="tabular-nums">${m.tp}</td>
          <td class="tabular-nums">${m.fp > 0 ? `<span class="tag tag-warn">${m.fp}</span>` : "0"}</td>
          <td class="tabular-nums">${m.fn > 0 ? `<span class="tag tag-warn">${m.fn}</span>` : "0"}</td>
          <td class="tabular-nums">${m.support}</td>
          <td class="tabular-nums">
            <div class="conf-bar-wrap">
              <div class="conf-bar"><div class="conf-fill ${m.precision < 0.9 ? "high" : ""}" style="width:${pPct}%"></div></div>
              <span>${formatPct(m.precision)}</span>
            </div>
          </td>
          <td class="tabular-nums">
            <div class="conf-bar-wrap">
              <div class="conf-bar"><div class="conf-fill ${m.recall < 0.9 ? "high" : ""}" style="width:${rPct}%"></div></div>
              <span>${formatPct(m.recall)}</span>
            </div>
          </td>
          <td class="tabular-nums"><strong>${formatPct(m.f1)}</strong> (${fPct})</td>
        </tr>
      `;
    })
    .join("");

  const verdictFilter = document.getElementById("eval-verdict-filter").value;
  const rows = ev.field_comparisons.filter((row) => {
    if (verdictFilter === "ALL") return true;
    if (verdictFilter === "DISAGREEMENTS") return row.verdict !== "MATCH";
    return row.verdict === verdictFilter;
  });

  const tbody = document.getElementById("eval-fields-tbody");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="body-muted">No fields match this verdict filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows
    .map((row) => {
      const isMismatch = row.verdict !== "MATCH";
      const opts = ALL_CLASSES.map(
        (c) => `<option value="${c}" ${row.true_class === c ? "selected" : ""}>${c}</option>`
      ).join("");
      return `
        <tr class="${isMismatch ? "row-gap" : ""}" data-gt-key="${escapeHtml(row.field_key)}">
          <td>
            <div class="field-title">${escapeHtml(row.column)}</div>
            <div class="field-container">[${escapeHtml(row.source_type)}] ${escapeHtml(row.container)}</div>
          </td>
          <td>${classTagHtml(row.predicted_class)}</td>
          <td class="tabular-nums">${row.confidence.toFixed(2)}</td>
          <td>
            <span class="tag ${isMismatch ? "tag-accent" : ""}">${escapeHtml(row.verdict)}</span>
          </td>
          <td>
            <select class="js-gt-select" aria-label="Ground truth class for ${escapeHtml(row.column)}">${opts}</select>
          </td>
          <td class="body-muted">${escapeHtml(row.rationale || "—")}</td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll(".js-gt-select").forEach((sel) => {
    sel.addEventListener("change", async () => {
      const tr = sel.closest("tr");
      const key = tr.dataset.gtKey;
      const existing = appState.ground_truth.find((g) => g.field_key === key);
      if (!existing) return;
      const payload = {
        ...existing,
        true_class: sel.value,
      };
      try {
        appState = await apiRequest("/api/ground-truth", {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        renderAll();
        showToast(`Updated ground-truth label for ${existing.column} -> ${sel.value}`);
      } catch (err) {
        showToast(`Error: ${err.message}`);
      }
    });
  });
}

/* ---------------- VIEW 4: SOURCES, RULES & PSEUDOCODE ---------------- */
function renderSourcesAndRulesView() {
  const sourcesGrid = document.getElementById("sources-grid");
  sourcesGrid.innerHTML = appState.sources
    .map((src) => {
      const colsHtml = src.columns.map((c) => `<span class="tag">${escapeHtml(c)}</span>`).join("");
      const previewHeaders = src.columns.map((c) => `<th>${escapeHtml(c)}</th>`).join("");
      const previewRows = src.preview_rows
        .map(
          (row) =>
            `<tr>${src.columns.map((c) => `<td class="sample-code">${escapeHtml(row[c] ?? "")}</td>`).join("")}</tr>`
        )
        .join("");

      const deleteBtn =
        src.source_type === "CSV"
          ? `<button class="btn btn-sm btn-outline js-delete-csv" data-filename="${escapeHtml(src.container)}" type="button">REMOVE CSV</button>`
          : `<span class="tag tag-muted">EMBEDDED SQLITE</span>`;

      return `
        <article class="source-card">
          <div class="source-card-head">
            <div>
              <span class="tag ${src.source_type === "SQL" ? "tag-ink" : ""}">${escapeHtml(src.source_type)}</span>
              <h3 class="sub-title">${escapeHtml(src.container)}</h3>
              <span class="label-xs tabular-nums">${src.column_count} COLUMNS &bull; ${src.row_count} ROWS</span>
            </div>
            ${deleteBtn}
          </div>
          <div class="source-cols">${colsHtml}</div>
          <div class="table-wrap">
            <table class="swiss-table">
              <thead><tr>${previewHeaders}</tr></thead>
              <tbody>${previewRows}</tbody>
            </table>
          </div>
        </article>
      `;
    })
    .join("");

  sourcesGrid.querySelectorAll(".js-delete-csv").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const filename = btn.dataset.filename;
      try {
        appState = await apiRequest(`/api/sources/csv/${encodeURIComponent(filename)}`, {
          method: "DELETE",
        });
        renderAll();
        showToast(`Removed CSV: ${filename}`);
      } catch (err) {
        showToast(`Error: ${err.message}`);
      }
    });
  });

  draftRules = structuredClone(appState.rules);
  renderRulesList();
}

function renderRulesList() {
  const container = document.getElementById("rules-editor-list");
  container.innerHTML = draftRules
    .map((rule, idx) => {
      const classOptions = ALL_CLASSES.filter((c) => c !== "NONE")
        .map((c) => `<option value="${c}" ${rule.data_class === c ? "selected" : ""}>${c}</option>`)
        .join("");

      return `
        <div class="rule-card" data-rule-idx="${idx}">
          <div class="rule-card-grid">
            <div>
              <label class="label-xs">RULE NAME</label>
              <input class="js-rule-name" type="text" value="${escapeHtml(rule.name)}" />
            </div>
            <div>
              <label class="label-xs">DATA CLASS</label>
              <select class="js-rule-class">${classOptions}</select>
            </div>
            <div>
              <label class="label-xs">COL WEIGHT</label>
              <input class="js-rule-col-w" type="number" step="0.05" min="0" max="1" value="${rule.column_weight}" />
            </div>
            <div>
              <label class="label-xs">VAL WEIGHT</label>
              <input class="js-rule-val-w" type="number" step="0.05" min="0" max="1" value="${rule.value_weight}" />
            </div>
            <div>
              <label class="label-xs">MIN VAL RATIO</label>
              <input class="js-rule-ratio" type="number" step="0.05" min="0" max="1" value="${rule.min_value_match_ratio}" />
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
              <label style="display:flex; align-items:center; gap:5px; font-family:var(--font-mono); font-size:11px; cursor:pointer;">
                <input class="js-rule-enabled" type="checkbox" ${rule.enabled ? "checked" : ""} /> ACTIVE
              </label>
              <button class="btn btn-sm btn-outline js-delete-rule" type="button">DEL</button>
            </div>
          </div>
          <div class="rule-patterns-grid">
            <div>
              <label class="label-xs">COLUMN NAME REGEX</label>
              <input class="js-rule-col-pat mono-readout" type="text" value="${escapeHtml(rule.column_pattern)}" />
            </div>
            <div>
              <label class="label-xs">SAMPLE VALUE REGEX</label>
              <input class="js-rule-val-pat mono-readout" type="text" value="${escapeHtml(rule.value_pattern)}" />
            </div>
            <div>
              <label class="label-xs">NOTES</label>
              <input class="js-rule-notes" type="text" value="${escapeHtml(rule.notes || "")}" />
            </div>
          </div>
        </div>
      `;
    })
    .join("");

  container.querySelectorAll(".js-delete-rule").forEach((btn) => {
    btn.addEventListener("click", () => {
      syncDraftRulesFromDom();
      const idx = Number(btn.closest(".rule-card").dataset.ruleIdx);
      draftRules.splice(idx, 1);
      renderRulesList();
    });
  });
}

function syncDraftRulesFromDom() {
  const cards = document.querySelectorAll("#rules-editor-list .rule-card");
  cards.forEach((card, idx) => {
    if (!draftRules[idx]) return;
    draftRules[idx].name = card.querySelector(".js-rule-name").value.trim() || draftRules[idx].id;
    draftRules[idx].data_class = card.querySelector(".js-rule-class").value;
    draftRules[idx].column_weight = Number(card.querySelector(".js-rule-col-w").value);
    draftRules[idx].value_weight = Number(card.querySelector(".js-rule-val-w").value);
    draftRules[idx].min_value_match_ratio = Number(card.querySelector(".js-rule-ratio").value);
    draftRules[idx].enabled = card.querySelector(".js-rule-enabled").checked;
    draftRules[idx].column_pattern = card.querySelector(".js-rule-col-pat").value;
    draftRules[idx].value_pattern = card.querySelector(".js-rule-val-pat").value;
    draftRules[idx].notes = card.querySelector(".js-rule-notes").value;
  });
}

/* ---------------- VIEW 5: SCOPE & EVIDENCE NOTICE ---------------- */
function renderScopeView() {
  const { does, does_not } = appState.scope_guardrail;
  document.getElementById("scope-does-list").innerHTML = does
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
  document.getElementById("scope-does-not-list").innerHTML = does_not
    .map((item) => `<li>${escapeHtml(item)}</li>`)
    .join("");
}

/* ---------------- SLIDE-OVER FIELD INSPECTOR DRAWER ---------------- */
function openDrawer(rec) {
  inspectedFieldKey = rec.field_key;
  showRawSamplesInDrawer = false;
  renderDrawer(rec);
  document.getElementById("inspector-drawer").classList.remove("hidden");
}

function closeDrawer() {
  inspectedFieldKey = null;
  document.getElementById("inspector-drawer").classList.add("hidden");
}

function renderDrawer(rec) {
  document.getElementById("drawer-title").textContent = `${rec.source_type} // ${rec.container}.${rec.column}`;
  const gtEntry = appState.ground_truth.find((g) => g.field_key === rec.field_key);
  const currentGt = gtEntry ? gtEntry.true_class : rec.predicted_class;
  const currentRationale = gtEntry ? gtEntry.rationale : "";

  const samples = showRawSamplesInDrawer ? rec.sample_values : rec.masked_samples;
  const matchedRulesHtml = rec.matched_rules.length
    ? rec.matched_rules
        .map(
          (m) => `
        <div style="border-top:1px solid rgba(30,30,30,0.2); padding:6px 0;">
          <div><strong>${escapeHtml(m.rule_name)}</strong> &rarr; ${classTagHtml(m.data_class)}</div>
          <div class="sample-code tabular-nums">
            col_match=${m.column_matched} &bull; val_ratio=${m.value_match_ratio} &bull; score=${m.score}
          </div>
        </div>`
        )
        .join("")
    : `<div class="body-muted">No rules crossed trigger threshold. Classified as NONE.</div>`;

  const gtOptions = ALL_CLASSES.map(
    (c) => `<option value="${c}" ${currentGt === c ? "selected" : ""}>${c}</option>`
  ).join("");

  document.getElementById("drawer-body").innerHTML = `
    <div class="drawer-section">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
        ${classTagHtml(rec.predicted_class)}
        ${gapTagHtml(rec.gap_status)}
      </div>
      <div class="mono-readout tabular-nums" style="margin-top:8px;">
        Confidence: ${rec.confidence.toFixed(3)} &bull; Non-null: ${rec.non_null_count}/${rec.row_count}
      </div>
      <p class="body-muted" style="margin-top:8px; margin-bottom:0;">${escapeHtml(rec.review_notice)}</p>
    </div>

    <div class="drawer-section">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h4>Sample Values (${showRawSamplesInDrawer ? "Synthetic Raw" : "Masked"})</h4>
        <button id="btn-toggle-mask" class="btn btn-sm btn-outline" type="button">
          ${showRawSamplesInDrawer ? "MASK VALUES" : "REVEAL SYNTHETIC"}
        </button>
      </div>
      <div class="sample-code">${samples.map((s) => `<div>&bull; ${escapeHtml(s)}</div>`).join("") || "No non-null values"}</div>
    </div>

    <div class="drawer-section">
      <h4>Matched Detection Rules</h4>
      ${matchedRulesHtml}
    </div>

    <div class="drawer-section">
      <h4>Purpose &amp; Retention Metadata</h4>
      <form id="drawer-meta-form" class="form-stack">
        <div>
          <label class="label-xs">DECLARED PURPOSE</label>
          <input id="dm-purpose" type="text" value="${escapeHtml(rec.declared_purpose)}" placeholder="e.g. Statutory tax filing" />
        </div>
        <div>
          <label class="label-xs">RETENTION SCHEDULE</label>
          <input id="dm-retention" type="text" value="${escapeHtml(rec.retention_schedule)}" placeholder="e.g. 5 years post closure" />
        </div>
        <div>
          <label class="label-xs">OWNER TEAM</label>
          <input id="dm-owner" type="text" value="${escapeHtml(rec.owner_team)}" placeholder="e.g. Trust & Safety" />
        </div>
        <button class="btn btn-accent btn-sm" type="submit">SAVE METADATA</button>
      </form>
    </div>

    <div class="drawer-section">
      <h4>Ground-Truth Benchmark Label</h4>
      <form id="drawer-gt-form" class="form-stack">
        <div>
          <label class="label-xs">HUMAN-VERIFIED TRUE CLASS</label>
          <select id="dgt-class">${gtOptions}</select>
        </div>
        <div>
          <label class="label-xs">RATIONALE</label>
          <input id="dgt-rationale" type="text" value="${escapeHtml(currentRationale)}" placeholder="Short justification..." />
        </div>
        <button class="btn btn-ink btn-sm" type="submit">SAVE GROUND TRUTH</button>
      </form>
    </div>
  `;

  document.getElementById("btn-toggle-mask").addEventListener("click", () => {
    showRawSamplesInDrawer = !showRawSamplesInDrawer;
    renderDrawer(rec);
  });

  document.getElementById("drawer-meta-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      appState = await apiRequest("/api/metadata", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          field_key: rec.field_key,
          source_type: rec.source_type,
          container: rec.container,
          column: rec.column,
          declared_purpose: document.getElementById("dm-purpose").value.trim(),
          retention_schedule: document.getElementById("dm-retention").value.trim(),
          owner_team: document.getElementById("dm-owner").value.trim(),
        }),
      });
      renderAll();
      showToast(`Metadata saved for ${rec.column}`);
    } catch (err) {
      showToast(`Error: ${err.message}`);
    }
  });

  document.getElementById("drawer-gt-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      appState = await apiRequest("/api/ground-truth", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          field_key: rec.field_key,
          source_type: rec.source_type,
          container: rec.container,
          column: rec.column,
          true_class: document.getElementById("dgt-class").value,
          rationale: document.getElementById("dgt-rationale").value.trim(),
        }),
      });
      renderAll();
      showToast(`Ground truth saved for ${rec.column}`);
    } catch (err) {
      showToast(`Error: ${err.message}`);
    }
  });
}

/* ---------------- EVENT BINDINGS & INIT ---------------- */
function bindEvents() {
  document.querySelectorAll(".nav-tab").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.dataset.view));
  });

  document.querySelectorAll(".subtab").forEach((btn) => {
    btn.addEventListener("click", () => switchSubtab(btn.dataset.subtab));
  });

  document.getElementById("btn-jump-rules").addEventListener("click", () => {
    switchView("sources");
    switchSubtab("sub-rules");
  });

  document.getElementById("btn-close-drawer").addEventListener("click", closeDrawer);

  document.getElementById("btn-run-scan").addEventListener("click", async () => {
    try {
      appState = await apiRequest("/api/scan", { method: "POST" });
      renderAll();
      showToast("Scan complete across all CSV & SQLite sources.");
    } catch (err) {
      showToast(`Scan error: ${err.message}`);
    }
  });

  document.getElementById("btn-reset-demo").addEventListener("click", async () => {
    try {
      appState = await apiRequest("/api/reset", { method: "POST" });
      selectedClassFilter = "ALL";
      renderAll();
      showToast(appState.last_action || "Demo environment reset.");
    } catch (err) {
      showToast(`Reset error: ${err.message}`);
    }
  });

  document.getElementById("inv-search").addEventListener("input", renderInventoryView);
  document.getElementById("inv-source-filter").addEventListener("change", renderInventoryView);
  document.getElementById("inv-gap-filter").addEventListener("change", renderInventoryView);
  document.getElementById("btn-clear-filters").addEventListener("click", () => {
    selectedClassFilter = "ALL";
    document.getElementById("inv-search").value = "";
    document.getElementById("inv-source-filter").value = "ALL";
    document.getElementById("inv-gap-filter").value = "ALL";
    renderInventoryView();
  });

  document.getElementById("gap-view-filter").addEventListener("change", renderGapsView);
  document.getElementById("eval-verdict-filter").addEventListener("change", renderEvaluationView);

  document.getElementById("form-generate-csv").addEventListener("submit", async (e) => {
    e.preventDefault();
    const filename = document.getElementById("gen-csv-name").value.trim() || null;
    const rows = Number(document.getElementById("gen-csv-rows").value) || 8;
    try {
      appState = await apiRequest("/api/sources/csv/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename, rows }),
      });
      document.getElementById("gen-csv-name").value = "";
      renderAll();
      showToast(appState.last_action || "Synthetic CSV generated.");
    } catch (err) {
      showToast(`Generate error: ${err.message}`);
    }
  });

  document.getElementById("form-upload-csv").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById("upload-csv-file");
    if (!fileInput.files.length) return;
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    try {
      appState = await apiRequest("/api/sources/csv/upload", {
        method: "POST",
        body: formData,
      });
      fileInput.value = "";
      renderAll();
      showToast(appState.last_action || "Uploaded and scanned CSV.");
    } catch (err) {
      showToast(`Upload error: ${err.message}`);
    }
  });

  document.getElementById("btn-add-rule").addEventListener("click", () => {
    syncDraftRulesFromDom();
    draftRules.push({
      id: `rule-custom-${Date.now().toString(36)}`,
      name: "Custom Detection Rule",
      data_class: "DIRECT_IDENTIFIER",
      column_pattern: "custom_field",
      value_pattern: "",
      column_weight: 0.65,
      value_weight: 0.45,
      min_value_match_ratio: 0.35,
      enabled: true,
      notes: "User-added rule.",
    });
    renderRulesList();
  });

  document.getElementById("btn-save-rules").addEventListener("click", async () => {
    syncDraftRulesFromDom();
    try {
      appState = await apiRequest("/api/rules", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(draftRules),
      });
      renderAll();
      showToast("Rules saved and full re-scan completed.");
    } catch (err) {
      showToast(`Rule save error: ${err.message}`);
    }
  });

  document.getElementById("btn-reset-rules").addEventListener("click", async () => {
    try {
      appState = await apiRequest("/api/rules/reset", { method: "POST" });
      renderAll();
      showToast("Detection rules restored to defaults.");
    } catch (err) {
      showToast(`Reset rules error: ${err.message}`);
    }
  });
}

async function init() {
  bindEvents();
  const params = new URLSearchParams(window.location.search);
  const initialView = params.get("view");
  if (initialView && document.getElementById(`view-${initialView}`)) {
    switchView(initialView);
  }
  const initialSubtab = params.get("subtab");
  if (initialSubtab && document.getElementById(initialSubtab)) {
    switchSubtab(initialSubtab);
  }
  try {
    appState = await apiRequest("/api/state");
    renderAll();
  } catch (err) {
    showToast(`Failed to load scanner state: ${err.message}`);
  }
}

init();
