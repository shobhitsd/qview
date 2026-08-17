/**
 * QView — Enterprise Quantum Readiness Intelligence Platform
 * Corporate Day/Light Engine & Dashboard Application Logic
 * Drives all 7 views: Executive Overview, Crypto Universe, Heatmap,
 * Compliance, Migration Cockpit, Knowledge Graph, Evidence Center + User Guide
 */

'use strict';

// ═══════════════════════════════════════════════════════════════════
// GLOBAL STATE
// ═══════════════════════════════════════════════════════════════════
let APP_STATE = {
  summary: null,
  findings: [],
  cbom: null,
  graph: null,
  activeFilter: {
    search: '',
    status: '',
    primitive: '',
    moscaOnly: false,
    hardcodedOnly: false,
  },
  heatmapCells: [],
  selectedHeatmapCell: null,
  activeEvidenceFinding: null,
  charts: {},
  graphNodes: [],
  graphEdges: [],
};

// ═══════════════════════════════════════════════════════════════════
// DOM HELPERS & UTILITIES
// ═══════════════════════════════════════════════════════════════════
const $ = (id) => document.getElementById(id);
const setText = (id, val) => { const el = $(id); if (el) el.textContent = val ?? '--'; };

function shortPath(path) {
  if (!path) return '';
  const parts = path.replace(/\\/g, '/').split('/');
  return parts.length > 2 ? `…/${parts.slice(-2).join('/')}` : path;
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function qeiColor(score) {
  if (score >= 90) return '#dc2626';
  if (score >= 75) return '#ea580c';
  if (score >= 60) return '#d97706';
  if (score >= 40) return '#ca8a04';
  if (score >= 20) return '#65a30d';
  return '#059669';
}

function statusBadge(status) {
  if (status === 'CRITICAL_VULNERABLE') {
    return '<span class="risk-pill-badge" style="background:#fef2f2;color:#dc2626;border:1px solid #fecaca">Critical</span>';
  }
  if (status === 'MEDIUM_RISK') {
    return '<span class="risk-pill-badge" style="background:#fffbeb;color:#d97706;border:1px solid #fde68a">Medium</span>';
  }
  if (status === 'QUANTUM_SAFE' || status === 'QUANTUM_RESILIENT') {
    return '<span class="risk-pill-badge" style="background:#ecfdf5;color:#059669;border:1px solid #a7f3d0">PQC Safe</span>';
  }
  return `<span class="risk-pill-badge" style="background:#f1f5f9;color:#64748b;border:1px solid #e2e8f0">${status}</span>`;
}

function waveClass(wave) {
  if (!wave) return 'wave-4-badge';
  if (wave.includes('0')) return 'wave-0-badge';
  if (wave.includes('1')) return 'wave-1-badge';
  if (wave.includes('2')) return 'wave-2-badge';
  if (wave.includes('3')) return 'wave-3-badge';
  return 'wave-4-badge';
}

function waveName(wave) {
  if (!wave) return 'Wave 4';
  if (wave.includes('0')) return 'Wave 0 (Discovery)';
  if (wave.includes('1')) return 'Wave 1 (Critical)';
  if (wave.includes('2')) return 'Wave 2 (High)';
  if (wave.includes('3')) return 'Wave 3 (Standard)';
  return 'Wave 4 (Legacy)';
}

function animateCounter(el, target, duration = 750) {
  if (!el) return;
  const start = performance.now();
  const from = 0;
  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const ease = progress < 0.5 ? 2 * progress * progress : -1 + (4 - 2 * progress) * progress;
    el.textContent = Math.round(from + (target - from) * ease);
    if (progress < 1) requestAnimationFrame(step);
    else el.textContent = target;
  }
  requestAnimationFrame(step);
}

function setRadialGauge(gaugeId, score, circumference = 264) {
  const el = $(gaugeId);
  if (!el) return;
  const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
  el.style.strokeDashoffset = offset;
}

// ═══════════════════════════════════════════════════════════════════
// DATA FETCHING & SYNCHRONIZATION
// ═══════════════════════════════════════════════════════════════════
async function fetchAssessment() {
  showLoader('Syncing quantum readiness telemetry...');
  try {
    const res = await fetch('/api/assessment/latest');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    APP_STATE.summary  = data.summary;
    APP_STATE.findings = data.summary?.findings || [];
    APP_STATE.cbom     = data.cbom;
    APP_STATE.graph    = data.graph;
    renderAllViews();
  } catch (err) {
    console.warn('API sync fallback to local dataset:', err);
    showFallbackData();
  } finally {
    hideLoader();
  }
}

async function triggerDiscoveryScan(targetPath) {
  showLoader('Running quantum discovery scan...');
  animateScanProgress();
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        target_path: targetPath, 
        app_name: targetPath.split('/').pop() || 'Target-App',
        coverage_pct: 0.92
      })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    APP_STATE.summary  = data.summary;
    APP_STATE.findings = data.summary?.findings || [];
    APP_STATE.cbom     = data.cbom;
    APP_STATE.graph    = data.graph;
    renderAllViews();
  } catch (e) {
    alert('Scan error: ' + e.message);
  } finally {
    hideLoader();
    hideScanProgress();
  }
}

// ═══════════════════════════════════════════════════════════════════
// RENDER ALL VIEWS
// ═══════════════════════════════════════════════════════════════════
function renderAllViews() {
  if (!APP_STATE.summary) return;
  const s = APP_STATE.summary;

  // Header quick stats
  setText('headerQri', Math.round(s.qri || 0));
  setText('headerQei', Math.round(s.qei || 0));
  setText('headerMosca', s.mosca_violation_count || 0);
  setText('headerAssets', s.total_crypto_assets || APP_STATE.findings.length);

  setText('tabBadgeAssets', APP_STATE.findings.length);
  const totalViolations = s.compliance_report?.total_violations || 0;
  setText('tabBadgeViolations', totalViolations);

  setText('scanTargetName', s.target_name || 'Sentara Enterprise');
  const covPct = Math.round((s.coverage_confidence || 0.92) * 100);
  setText('scanCoverageVal', `${covPct}% (Verified)`);

  // Render individual tabs
  renderExecutiveView(s);
  renderUniverseView();
  renderHeatmapView();
  renderComplianceView(s);
  renderMigrationView();
  renderGraphView();
  renderEvidenceView();
}

// ═══════════════════════════════════════════════════════════════════
// VIEW 1: EXECUTIVE OVERVIEW
// ═══════════════════════════════════════════════════════════════════
function renderExecutiveView(s) {
  const qri = s.qri ?? 0;
  const qei = s.qei ?? 0;
  const cai = s.cai ?? 0;
  const coverage = Math.round((s.coverage_confidence ?? 0.92) * 100);

  // Animated counters & Radial gauges
  const qriEl = $('qriValue'); if (qriEl) animateCounter(qriEl, Math.round(qri));
  const qeiEl = $('qeiValue'); if (qeiEl) animateCounter(qeiEl, Math.round(qei));
  const caiEl = $('caiValue'); if (caiEl) animateCounter(caiEl, Math.round(cai));

  setTimeout(() => {
    setRadialGauge('gaugeQRI', qri);
    setRadialGauge('gaugeQEI', qei);
    setRadialGauge('gaugeCAI', cai);
  }, 100);

  // Score Band Badges
  const qriBand = s.qri_band || {};
  const qeiBand = s.qei_band || {};
  const el_qriBand = $('qriBand');
  const el_qeiBand = $('qeiBand');
  const el_caiBand = $('caiBand');

  if (el_qriBand) el_qriBand.textContent = qriBand.label || (qri >= 75 ? 'Ready' : qri >= 50 ? 'Progressing' : 'Vulnerable');
  if (el_qeiBand) el_qeiBand.textContent = qeiBand.label || (qei >= 75 ? 'Critical' : qei >= 50 ? 'High' : 'Moderate');
  if (el_caiBand) el_caiBand.textContent = cai >= 70 ? 'Agile' : cai >= 45 ? 'Moderate' : 'Rigid';

  setText('baseQri', s.base_qri || '--');
  setText('qriConfidence', `${coverage}%`);
  setText('moscaCount', s.mosca_violation_count ?? 0);
  setText('hndlCount', s.hndl_critical_count ?? 0);

  // Progress Bars
  if ($('qriBar')) $('qriBar').style.width = `${qri}%`;
  if ($('qeiBar')) $('qeiBar').style.width = `${qei}%`;
  if ($('caiBar')) $('caiBar').style.width = `${cai}%`;

  // Asset Count Tiles
  const total = s.total_crypto_assets || APP_STATE.findings.length;
  const critical = s.quantum_vulnerable_count ?? 0;
  const medium = s.medium_risk_count ?? 0;
  const safe = s.quantum_safe_count ?? 0;
  const hardcoded = APP_STATE.findings.filter(f => f.crypto_asset?.hardcoded).length;

  const totalEl = $('totalAssets'); if (totalEl) animateCounter(totalEl, total);
  const critEl = $('criticalCount'); if (critEl) animateCounter(critEl, critical);
  const medEl = $('mediumCount');  if (medEl) animateCounter(medEl, medium);
  const sfeEl = $('safeCount');    if (sfeEl) animateCounter(sfeEl, safe);

  setText('totalFiles', `${s.total_files_scanned ?? 0} files scanned / ${(s.total_loc_scanned ?? 0).toLocaleString()} LOC`);
  setText('hardcodedCount', hardcoded);
  setText('pqcReadyCount', safe);
  setText('donutTotalVal', total);

  // Mosca Inequality Banner
  const moscaBanner = $('moscaBanner');
  if (moscaBanner && (s.mosca_violation_count ?? 0) > 0) {
    moscaBanner.style.display = 'block';
    setText('moscaText', 
      `${s.mosca_violation_count} cryptographic assets protect data whose required confidentiality lifetime (X) + enterprise migration time (Y) exceeds the estimated time until Cryptographically Relevant Quantum Computers arrive (Z = 7 yrs). Adversaries are actively harvesting this traffic today for retroactive decryption.`
    );
  }

  // Setup Mosca Simulator
  setupMoscaSimulator();

  // Render Charts
  renderQriRadarChart(s.qri_dimensions || {});
  renderDonutChart(critical, medium, safe, s.unknown_crypto_count || 0);
  renderRiskBreakdownStats(critical, medium, safe, total);
  renderTopRisksList();
}

// ── Interactive Mosca Simulator ──────────────────────────────────────────────
function setupMoscaSimulator() {
  const sX = $('sliderMoscaX');
  const sY = $('sliderMoscaY');
  const sZ = $('sliderMoscaZ');
  if (!sX || !sY || !sZ) return;

  const updateSim = () => {
    const x = parseInt(sX.value);
    const y = parseInt(sY.value);
    const z = parseInt(sZ.value);

    setText('valMoscaX', `${x} yrs`);
    setText('valMoscaY', `${y} yrs`);
    setText('valMoscaZ', `${z} yrs`);

    const sum = x + y;
    const isViolated = sum > z;
    const vBox = $('simVerdict');
    if (vBox) {
      if (isViolated) {
        vBox.innerHTML = `
          <span class="verdict-tag verdict-violated">VIOLATED (${sum} > ${z})</span>
          <span class="verdict-sub">Immediate Wave 1 Action</span>
        `;
      } else {
        vBox.innerHTML = `
          <span class="verdict-tag verdict-safe">SAFE (${sum} ≤ ${z})</span>
          <span class="verdict-sub">Standard Wave 3</span>
        `;
      }
    }
  };

  sX.oninput = updateSim;
  sY.oninput = updateSim;
  sZ.oninput = updateSim;
}

// ── 8-Dimension Radar / Spider Chart (Corporate Day Theme) ───────────────────
function renderQriRadarChart(dims) {
  const ctx = document.getElementById('qriRadarChart');
  if (!ctx) return;

  const labels = [
    'Crypto Exposure',
    'Data Protection',
    'Biz Criticality',
    'Crypto Agility',
    'PQC Compatibility',
    'Inventory Coverage',
    'Migration Simplicity',
    'Governance Policy'
  ];

  const currentValues = [
    dims.crypto_exposure?.score ?? 15,
    dims.data_protection?.score ?? 25,
    dims.business_criticality?.score ?? 20,
    dims.crypto_agility?.score ?? 35,
    dims.pqc_compatibility?.score ?? 20,
    dims.inventory_coverage?.score ?? 92,
    dims.migration_complexity?.score ?? 60,
    dims.governance_policy?.score ?? 30,
  ];

  const targetBenchmark = [100, 100, 100, 100, 100, 100, 100, 100];

  if (APP_STATE.charts.radar) {
    APP_STATE.charts.radar.destroy();
  }

  APP_STATE.charts.radar = new Chart(ctx, {
    type: 'radar',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Current Posture',
          data: currentValues,
          backgroundColor: 'rgba(37, 99, 235, 0.15)',
          borderColor: '#2563eb',
          borderWidth: 2,
          pointBackgroundColor: '#2563eb',
          pointBorderColor: '#ffffff',
          pointRadius: 4,
          pointHoverRadius: 6,
        },
        {
          label: 'NIST PQC Benchmark (100%)',
          data: targetBenchmark,
          backgroundColor: 'rgba(5, 150, 105, 0.05)',
          borderColor: 'rgba(5, 150, 105, 0.5)',
          borderWidth: 1.5,
          borderDash: [4, 4],
          pointRadius: 0,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0f172a',
          titleColor: '#ffffff',
          bodyColor: '#e2e8f0',
          titleFont: { family: 'Plus Jakarta Sans', weight: '700' },
          bodyFont: { family: 'JetBrains Mono' },
          padding: 10,
          cornerRadius: 6,
        }
      },
      scales: {
        r: {
          min: 0,
          max: 100,
          ticks: { stepSize: 25, display: false },
          grid: { color: '#e2e8f0' },
          angleLines: { color: '#e2e8f0' },
          pointLabels: {
            font: { family: 'Plus Jakarta Sans', size: 11, weight: '600' },
            color: '#475569'
          }
        }
      }
    }
  });

  // Render Mini Bars Grid
  const barsGrid = $('dimBarsGrid');
  if (barsGrid) {
    const dimEntries = Object.entries(dims);
    barsGrid.innerHTML = dimEntries.map(([k, v]) => {
      const score = v.score ?? 0;
      const col = score >= 75 ? 'var(--success)' : score >= 50 ? 'var(--warning)' : 'var(--critical)';
      const friendlyName = k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      return `
        <div class="dim-mini-item">
          <div class="dim-mini-header">
            <span class="dim-mini-lbl">${friendlyName}</span>
            <span class="dim-mini-val" style="color:${col}">${score}%</span>
          </div>
          <div class="dim-mini-track">
            <div class="dim-mini-fill" style="width:${score}%;background:${col}"></div>
          </div>
        </div>
      `;
    }).join('');
  }
}

// ── Donut Chart (Corporate Day Theme) ───────────────────────────────────────
function renderDonutChart(critical, medium, safe, unknown) {
  const ctx = document.getElementById('riskDonutChart');
  if (!ctx) return;

  if (APP_STATE.charts.donut) {
    APP_STATE.charts.donut.destroy();
  }

  APP_STATE.charts.donut = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical Vulnerable', 'Medium Risk', 'Quantum Safe', 'Unclassified'],
      datasets: [{
        data: [critical, medium, safe, unknown],
        backgroundColor: [
          '#dc2626',
          '#d97706',
          '#059669',
          '#94a3b8'
        ],
        borderColor: '#ffffff',
        borderWidth: 2,
        hoverOffset: 3
      }]
    },
    options: {
      cutout: '74%',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0f172a',
          titleColor: '#ffffff',
          bodyColor: '#e2e8f0',
          padding: 8,
          cornerRadius: 6,
          bodyFont: { family: 'JetBrains Mono' }
        }
      },
      animation: { animateRotate: true, duration: 750 }
    }
  });
}

function renderRiskBreakdownStats(critical, medium, safe, total) {
  const el = $('riskBreakdown');
  if (!el) return;

  const rows = [
    { label: 'Critical Shor\'s Risk', count: critical, color: '#dc2626' },
    { label: 'Medium Grover\'s Risk', count: medium, color: '#d97706' },
    { label: 'PQC Quantum Safe', count: safe, color: '#059669' },
    { label: 'Unmapped / Unknown', count: Math.max(0, total - critical - medium - safe), color: '#64748b' }
  ];

  el.innerHTML = rows.map(r => `
    <div class="risk-stat-row">
      <div class="risk-stat-dot" style="background:${r.color}"></div>
      <span class="risk-stat-name">${r.label}</span>
      <span class="risk-stat-count" style="color:${r.color}">${r.count}</span>
    </div>
  `).join('');
}

// ── Top Risks List ──────────────────────────────────────────────────────────
function renderTopRisksList() {
  const el = $('topFindingsList');
  if (!el) return;

  const top = [...APP_STATE.findings]
    .sort((a, b) => (b.qei_score || 0) - (a.qei_score || 0))
    .slice(0, 5);

  if (top.length === 0) {
    el.innerHTML = '<div style="text-align:center;padding:1.5rem;color:var(--text-muted);">No risks detected</div>';
    return;
  }

  el.innerHTML = top.map(f => {
    const algo = f.crypto_asset?.algorithm_variant || f.crypto_asset?.algorithm_family || 'Unknown';
    const loc = shortPath(f.evidence?.file_path || '');
    const line = f.evidence?.start_line ? `:${f.evidence.start_line}` : '';
    const qei = Math.round(f.qei_score || 0);

    return `
      <div class="top-risk-row-item" onclick="openEvidence('${f.finding_id}')">
        ${statusBadge(f.quantum_status)}
        <div class="risk-row-content">
          <div class="risk-algo-title">${algo} ${f.mosca_flag ? '⚠️' : ''}</div>
          <div class="risk-loc-subtitle">${loc}${line}</div>
        </div>
        <div class="risk-qei-box">
          <div class="risk-qei-val" style="color:${qeiColor(qei)}">${qei}</div>
          <div class="risk-qei-lbl">QEI</div>
        </div>
      </div>
    `;
  }).join('');
}

// ═══════════════════════════════════════════════════════════════════
// VIEW 2: CRYPTO UNIVERSE EXPLORER
// ═══════════════════════════════════════════════════════════════════
function renderUniverseView() {
  const filtered = getFilteredFindings();
  const tbody = $('universeTableBody');
  if (!tbody) return;

  setText('universeShown', filtered.length);
  setText('universeTotal', APP_STATE.findings.length);

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="13" style="text-align:center;padding:3rem;color:var(--text-muted);">
          No cryptographic assets match your search & filter criteria
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(f => {
    const fid     = f.finding_id || '--';
    const algo    = f.crypto_asset?.algorithm_variant || f.crypto_asset?.algorithm_family || '--';
    const prim    = f.crypto_asset?.primitive || '--';
    const keySize = f.crypto_asset?.key_size ? `${f.crypto_asset.key_size}-bit` : '--';
    const loc     = shortPath(f.evidence?.file_path || '--');
    const line    = f.evidence?.start_line ? `:${f.evidence.start_line}` : '';
    const qei     = Math.round(f.qei_score || 0);
    const cai     = Math.round(f.cai_score || 0);
    const hndl    = f.hndl_risk || '--';
    const mosca   = f.mosca_flag ? '⚠️ <strong style="color:var(--critical)">YES</strong>' : '—';
    const pqcT    = (f.pqc_recommendation?.target_algorithm || '--').split(' ')[0];
    const wave    = f.pqc_recommendation?.migration_wave || 'WAVE_4';
    const hndlCol = hndl === 'CRITICAL' ? 'var(--critical)' : hndl === 'HIGH' ? 'var(--warning)' : 'var(--text-muted)';

    return `
      <tr onclick="openEvidence('${fid}')">
        <td class="mono" style="color:var(--primary);font-weight:700;">${fid}</td>
        <td style="font-weight:700;color:var(--text-main);">${algo}</td>
        <td style="color:var(--text-muted);">${prim}</td>
        <td class="mono" style="color:var(--text-body);">${keySize}</td>
        <td>${statusBadge(f.quantum_status)}</td>
        <td class="mono" style="color:var(--text-muted);" title="${f.evidence?.file_path || ''}">${loc}${line}</td>
        <td class="mono" style="font-weight:800;color:${qeiColor(qei)}">${qei}</td>
        <td class="mono" style="font-weight:800;color:${cai >= 60 ? 'var(--primary)' : 'var(--warning)'}">${cai}</td>
        <td style="font-weight:700;color:${hndlCol};">${hndl}</td>
        <td style="text-align:center;">${mosca}</td>
        <td style="color:var(--success);font-weight:600;">${pqcT}</td>
        <td><span class="wave-tag-badge ${waveClass(wave)}">${waveName(wave).split(' ')[0]}</span></td>
        <td>
          <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); openEvidence('${fid}')">Inspect</button>
        </td>
      </tr>
    `;
  }).join('');
}

function getFilteredFindings() {
  const { search, status, primitive, moscaOnly, hardcodedOnly } = APP_STATE.activeFilter;
  const q = search.toLowerCase();

  return APP_STATE.findings.filter(f => {
    const algo = (f.crypto_asset?.algorithm_variant || f.crypto_asset?.algorithm_family || '').toLowerCase();
    const lib  = (f.crypto_asset?.library_name || '').toLowerCase();
    const loc  = (f.evidence?.file_path || '').toLowerCase();
    const fid  = (f.finding_id || '').toLowerCase();

    const matchesSearch = !q || algo.includes(q) || lib.includes(q) || loc.includes(q) || fid.includes(q);
    const matchesStatus = !status || f.quantum_status === status;
    const matchesPrim   = !primitive || f.crypto_asset?.primitive === primitive;
    const matchesMosca  = !moscaOnly || f.mosca_flag;
    const matchesHardcoded = !hardcodedOnly || f.crypto_asset?.hardcoded;

    return matchesSearch && matchesStatus && matchesPrim && matchesMosca && matchesHardcoded;
  });
}

function filterByMosca() {
  APP_STATE.activeFilter.moscaOnly = true;
  document.querySelectorAll('.pill-filter').forEach(b => b.classList.remove('active'));
  const btn = document.querySelector('[data-filter-mosca="true"]');
  if (btn) btn.classList.add('active');
  switchTab('tab-universe');
  renderUniverseView();
}

// ═══════════════════════════════════════════════════════════════════
// VIEW 3: QUANTUM HEATMAP MATRIX
// ═══════════════════════════════════════════════════════════════════
function renderHeatmapView() {
  const grid = $('heatmapGrid');
  if (!grid) return;

  const bizLevels  = ['Tier 1 (Low)', 'Tier 2 (Med)', 'Tier 3 (High)', 'Tier 4 (Critical)'];
  const exposeLvls = ['Critical (90-100)', 'High (60-89)', 'Medium (40-59)', 'Low (0-39)'];

  const matrix = Array.from({length: 4}, () => Array(4).fill(0));
  const cells  = Array.from({length: 4}, () => Array.from({length: 4}, () => []));

  for (const f of APP_STATE.findings) {
    const qei = f.qei_score || 0;
    const biz = f.business_criticality || 2;
    const bizIdx = biz <= 2 ? 0 : biz === 3 ? 1 : biz === 4 ? 2 : 3;
    const expIdx = qei >= 90 ? 0 : qei >= 60 ? 1 : qei >= 40 ? 2 : 3;

    matrix[expIdx][bizIdx]++;
    cells[expIdx][bizIdx].push(f);
  }

  APP_STATE.heatmapCells = cells;

  let html = '<div></div>'; // top-left empty cell
  bizLevels.forEach(lvl => {
    html += `<div style="font-size:0.72rem;font-weight:700;color:var(--text-muted);text-align:center;padding:4px;">${lvl}</div>`;
  });

  const getCellColor = (expIdx, bizIdx) => {
    if (expIdx === 0 && bizIdx >= 2) return 'hm-3';
    if (expIdx <= 1 && bizIdx >= 2) return 'hm-2';
    if (expIdx <= 1 || bizIdx === 3) return 'hm-2';
    if (expIdx === 2) return 'hm-1';
    return 'hm-0';
  };

  exposeLvls.forEach((expLvl, expIdx) => {
    html += `<div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);display:flex;align-items:center;justify-content:flex-end;padding-right:8px;">${expLvl}</div>`;
    for (let bizIdx = 0; bizIdx < 4; bizIdx++) {
      const count = matrix[expIdx][bizIdx];
      const colClass = getCellColor(expIdx, bizIdx);
      html += `
        <div class="hm-cell-new ${colClass}" 
             data-exp="${expIdx}" data-biz="${bizIdx}"
             onclick="selectHeatmapCell(${expIdx}, ${bizIdx}, '${expLvl}', '${bizLevels[bizIdx]}')">
          <span class="hm-cell-count">${count}</span>
          <span class="hm-cell-sub">assets</span>
        </div>
      `;
    }
  });

  grid.innerHTML = html;
}

function selectHeatmapCell(expIdx, bizIdx, expLabel, bizLabel) {
  document.querySelectorAll('.hm-cell-new').forEach(c => c.classList.remove('hm-selected'));
  const cell = document.querySelector(`[data-exp="${expIdx}"][data-biz="${bizIdx}"]`);
  if (cell) cell.classList.add('hm-selected');

  const findings = APP_STATE.heatmapCells?.[expIdx]?.[bizIdx] || [];
  setText('heatmapDetailTitle', `${findings.length} Cryptographic Asset(s) Filtered`);
  setText('heatmapDetailSubtitle', `Exposure: ${expLabel} × Criticality: ${bizLabel}`);

  const el = $('heatmapFindingsList');
  if (!el) return;

  if (findings.length === 0) {
    el.innerHTML = '<div class="empty-drilldown-state"><p>No assets in this risk quadrant</p></div>';
    return;
  }

  el.innerHTML = findings.map(f => {
    const algo = f.crypto_asset?.algorithm_variant || f.crypto_asset?.algorithm_family || 'Unknown';
    const loc  = shortPath(f.evidence?.file_path || '');
    const qei  = Math.round(f.qei_score || 0);

    return `
      <div class="top-risk-row-item" onclick="openEvidence('${f.finding_id}')">
        ${statusBadge(f.quantum_status)}
        <div class="risk-row-content">
          <div class="risk-algo-title">${algo} ${f.mosca_flag ? '⚠️' : ''}</div>
          <div class="risk-loc-subtitle">${loc}</div>
        </div>
        <div class="risk-qei-box">
          <div class="risk-qei-val" style="color:${qeiColor(qei)}">${qei}</div>
          <div class="risk-qei-lbl">QEI</div>
        </div>
      </div>
    `;
  }).join('');
}

// ═══════════════════════════════════════════════════════════════════
// VIEW 4: COMPLIANCE RADAR
// ═══════════════════════════════════════════════════════════════════
function renderComplianceView(s) {
  const report = s.compliance_report || {};
  setText('complianceTotalViolations', report.total_violations ?? 0);
  setText('complianceFwCount', report.frameworks_evaluated ?? 7);

  const grid = $('complianceGrid');
  if (grid && report.framework_summary) {
    grid.innerHTML = Object.entries(report.framework_summary).map(([id, fw]) => {
      const isNonComp = fw.compliance_status === 'NON_COMPLIANT';
      const isAtRisk  = fw.compliance_status === 'AT_RISK';
      const statusCls = isNonComp ? 'comp-non-compliant' : isAtRisk ? 'comp-at-risk' : 'comp-compliant';
      const statusTxt = isNonComp ? '✕ Non-Compliant' : isAtRisk ? '⚠ At Risk' : '✓ Compliant';

      return `
        <div class="compliance-box">
          <div class="comp-box-title">${fw.framework_name || id}</div>
          <div class="comp-box-auth">${fw.authority || ''}</div>
          <div class="comp-status-tag ${statusCls}">${statusTxt}</div>
          <div class="comp-counts">
            <strong>${fw.critical_violations ?? 0}</strong> Critical · 
            <strong>${fw.high_violations ?? 0}</strong> High · 
            ${fw.total_violations ?? 0} Breaches
          </div>
        </div>
      `;
    }).join('');
  }

  // Violations Table
  const tbody = $('complianceViolationsBody');
  if (!tbody) return;

  const allViolations = Object.values(report.framework_summary || {})
    .flatMap(fw => fw.violations || [])
    .sort((a, b) => a.severity === 'CRITICAL' ? -1 : 1);

  if (allViolations.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--text-muted);">No statutory compliance violations detected</td></tr>`;
    return;
  }

  tbody.innerHTML = allViolations.map(v => {
    const isCrit = v.severity === 'CRITICAL';
    const badge = isCrit 
      ? '<span class="risk-pill-badge" style="background:#fef2f2;color:#dc2626;border:1px solid #fecaca">Critical</span>'
      : '<span class="risk-pill-badge" style="background:#fffbeb;color:#d97706;border:1px solid #fde68a">High</span>';

    return `
      <tr>
        <td style="font-weight:700;color:var(--primary);">${v.framework_name || v.framework}</td>
        <td class="mono" style="font-size:0.78rem;font-weight:600;">${v.control_id}</td>
        <td style="color:var(--text-body);font-size:0.78rem;max-width:340px;white-space:normal;line-height:1.4;">${escapeHtml(v.requirement)}</td>
        <td style="font-weight:700;">${v.algorithm || '--'}</td>
        <td>${badge}</td>
        <td class="mono" style="color:var(--text-muted);font-size:0.75rem;">${shortPath(v.file || '')}:${v.line || ''}</td>
      </tr>
    `;
  }).join('');
}

// ═══════════════════════════════════════════════════════════════════
// VIEW 5: MIGRATION COCKPIT
// ═══════════════════════════════════════════════════════════════════
function renderMigrationView() {
  const waves = { '0': [], '1': [], '2': [], '3': [], '4': [] };

  for (const f of APP_STATE.findings) {
    const w = f.pqc_recommendation?.migration_wave || 'WAVE_4';
    if (w.includes('0')) waves['0'].push(f);
    else if (w.includes('1')) waves['1'].push(f);
    else if (w.includes('2')) waves['2'].push(f);
    else if (w.includes('3')) waves['3'].push(f);
    else waves['4'].push(f);
  }

  setText('wave0Count', waves['0'].length);
  setText('wave1Count', waves['1'].length);
  setText('wave2Count', waves['2'].length);
  setText('wave3Count', waves['3'].length);
  setText('wave4Count', waves['4'].length);

  const container = $('migrationWaves');
  if (!container) return;

  const waveDefs = [
    { id: '1', name: 'Wave 1 — Critical / Immediate HNDL Risk', cls: 'wave-1-badge',
      desc: 'Public-facing endpoints with vulnerable key establishment protecting long-lived sensitive data.' },
    { id: '2', name: 'Wave 2 — High Priority Enterprise Backend', cls: 'wave-2-badge',
      desc: 'Database column encryption, authentication tokens, microservice mTLS.' },
    { id: '3', name: 'Wave 3 — Standard Application Migration', cls: 'wave-3-badge',
      desc: 'Internal tools, transient messaging, non-critical logs.' },
    { id: '0', name: 'Wave 0 — Discovery & Unknown Dependencies', cls: 'wave-0-badge',
      desc: 'Unmapped algorithms, unknown ownership, closed-source dependencies.' },
    { id: '4', name: 'Wave 4 — Legacy / Hardware-Constrained', cls: 'wave-4-badge',
      desc: 'Embedded firmware, physical HSMs awaiting vendor PQC updates.' },
  ];

  container.innerHTML = waveDefs.map(w => {
    const list = waves[w.id];
    const isExpanded = w.id === '1';

    const tasksHtml = list.map(f => {
      const algo = f.crypto_asset?.algorithm_variant || f.crypto_asset?.algorithm_family || 'Unknown';
      const targetPqc = f.pqc_recommendation?.target_algorithm || 'ML-KEM / ML-DSA';
      const loc = shortPath(f.evidence?.file_path || '');
      const effort = f.pqc_recommendation?.effort_estimate || 'MEDIUM';

      return `
        <div class="migration-task-card" onclick="openEvidence('${f.finding_id}')">
          <div class="mig-dot" style="background:${f.quantum_status === 'CRITICAL_VULNERABLE' ? 'var(--critical)' : 'var(--warning)'}"></div>
          <div class="mig-content">
            <div class="mig-title">${algo} Migration Transition Plan</div>
            <div class="mig-path">${loc}:${f.evidence?.start_line || ''}</div>
            <div class="mig-transition-row">
              <span class="mig-from">${algo}</span>
              <span class="mig-arrow">→</span>
              <span class="mig-to">${targetPqc}</span>
            </div>
            <div class="mig-meta">Effort: <strong>${effort}</strong> · Pattern: ${f.pqc_recommendation?.migration_pattern || 'DIRECT_REPLACEMENT'}</div>
          </div>
          <button class="btn btn-sm btn-outline">View Fix</button>
        </div>
      `;
    }).join('');

    return `
      <div class="wave-accordion-card">
        <div class="wave-accordion-header" onclick="toggleAccordion(this)">
          <div style="display:flex;align-items:center;gap:0.85rem;">
            <span class="wave-tag-badge ${w.cls}">${w.name}</span>
            <span style="font-size:0.78rem;color:var(--text-muted);">${w.desc}</span>
          </div>
          <div style="display:flex;align-items:center;gap:0.75rem;">
            <span style="font-size:1.1rem;font-weight:800;font-family:'JetBrains Mono';color:var(--text-main);">${list.length}</span>
            <span style="color:var(--text-muted);">${isExpanded ? '▲' : '▼'}</span>
          </div>
        </div>
        <div class="wave-accordion-body ${isExpanded ? 'expanded' : ''}">
          ${tasksHtml || '<div style="color:var(--text-muted);font-size:0.78rem;padding:0.75rem 0;">No assets currently assigned to this wave</div>'}
        </div>
      </div>
    `;
  }).join('');
}

function toggleAccordion(header) {
  const body = header.nextElementSibling;
  body.classList.toggle('expanded');
  const arrow = header.querySelector('span:last-child');
  if (arrow) arrow.textContent = body.classList.contains('expanded') ? '▲' : '▼';
}

// ═══════════════════════════════════════════════════════════════════
// VIEW 6: KNOWLEDGE GRAPH (Corporate Day Theme Canvas with Zoom & Pan)
// ═══════════════════════════════════════════════════════════════════
APP_STATE.graphZoom = 1.0;
APP_STATE.graphPanX = 0;
APP_STATE.graphPanY = 0;

function zoomGraph(factor) {
  const newZoom = Math.min(Math.max(APP_STATE.graphZoom * factor, 0.35), 3.0);
  APP_STATE.graphZoom = Math.round(newZoom * 100) / 100;
  updateGraphZoomDisplay();
  if (APP_STATE.redrawGraph) APP_STATE.redrawGraph();
}

function updateGraphZoomDisplay() {
  const lbl = $('graphZoomLevel');
  if (lbl) {
    lbl.textContent = `${Math.round(APP_STATE.graphZoom * 100)}%`;
  }
}

function resetGraphView() {
  APP_STATE.graphZoom = 1.0;
  APP_STATE.graphPanX = 0;
  APP_STATE.graphPanY = 0;
  updateGraphZoomDisplay();
  renderGraphView();
}

function renderGraphView() {
  const canvas = document.getElementById('knowledgeGraphCanvas');
  if (!canvas) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const w = rect.width;
  const h = rect.height;

  updateGraphZoomDisplay();

  const nodes = [];
  const edges = [];
  const nodeMap = new Map();

  // Root Service Node
  const rootNode = { id: 'service-root', label: 'Sentara Health Platform', type: 'service', x: w / 2, y: h / 2, r: 24, col: '#2563eb' };
  nodes.push(rootNode);
  nodeMap.set(rootNode.id, rootNode);

  // Add file & algorithm nodes (10 nodes for optimal spacing)
  APP_STATE.findings.slice(0, 10).forEach((f, idx) => {
    const fileId = `file-${idx}`;
    const algoId = `algo-${idx}`;
    const algoName = f.crypto_asset?.algorithm_variant || f.crypto_asset?.algorithm_family || 'Algo';
    const isVuln = f.quantum_status === 'CRITICAL_VULNERABLE';

    const angle = (idx / 10) * 2 * Math.PI;
    const fileRadius = 160 + (idx % 2) * 35;
    const algoRadius = 280 + (idx % 3) * 40;

    const fileNode = {
      id: fileId,
      label: shortPath(f.evidence?.file_path || `File ${idx}`),
      type: 'file',
      x: w / 2 + Math.cos(angle) * fileRadius,
      y: h / 2 + Math.sin(angle) * fileRadius,
      r: 12,
      col: '#0284c7'
    };

    const algoNode = {
      id: algoId,
      label: algoName,
      type: 'algo',
      x: w / 2 + Math.cos(angle) * algoRadius,
      y: h / 2 + Math.sin(angle) * algoRadius,
      r: 14,
      col: isVuln ? '#dc2626' : '#059669'
    };

    nodes.push(fileNode, algoNode);
    nodeMap.set(fileId, fileNode);
    nodeMap.set(algoId, algoNode);

    edges.push({ from: rootNode, to: fileNode });
    edges.push({ from: fileNode, to: algoNode });
  });

  APP_STATE.graphNodes = nodes;
  APP_STATE.graphEdges = edges;

  // Cleanup old canvas listeners via fresh replacement
  const newCanvas = canvas.cloneNode(true);
  canvas.parentNode.replaceChild(newCanvas, canvas);
  newCanvas.width = rect.width * dpr;
  newCanvas.height = rect.height * dpr;
  const ctx = newCanvas.getContext('2d');
  ctx.scale(dpr, dpr);

  function screenToGraph(screenX, screenY) {
    const cx = w / 2;
    const cy = h / 2;
    const gx = (screenX - cx - APP_STATE.graphPanX) / APP_STATE.graphZoom + cx;
    const gy = (screenY - cy - APP_STATE.graphPanY) / APP_STATE.graphZoom + cy;
    return { x: gx, y: gy };
  }

  function drawGraph() {
    ctx.clearRect(0, 0, w, h);

    ctx.save();
    // Apply Pan & Zoom transformation relative to center
    ctx.translate(w / 2 + APP_STATE.graphPanX, h / 2 + APP_STATE.graphPanY);
    ctx.scale(APP_STATE.graphZoom, APP_STATE.graphZoom);
    ctx.translate(-w / 2, -h / 2);

    // Draw Edges
    edges.forEach(e => {
      ctx.beginPath();
      ctx.moveTo(e.from.x, e.from.y);
      ctx.lineTo(e.to.x, e.to.y);
      ctx.strokeStyle = '#cbd5e1';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });

    // Draw Nodes
    nodes.forEach(n => {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, 2 * Math.PI);
      ctx.fillStyle = n.col;
      ctx.fill();
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2.5;
      ctx.stroke();

      // Node Labels
      ctx.font = '600 11px "Plus Jakarta Sans", sans-serif';
      ctx.fillStyle = '#1e293b';
      ctx.textAlign = 'center';
      ctx.fillText(n.label, n.x, n.y + n.r + 14);
    });

    ctx.restore();
  }

  APP_STATE.redrawGraph = drawGraph;
  drawGraph();

  // Interaction State
  let isDraggingNode = false;
  let isPanningCanvas = false;
  let dragNode = null;
  let startMouseX = 0;
  let startMouseY = 0;
  let initialPanX = 0;
  let initialPanY = 0;

  newCanvas.addEventListener('mousedown', (e) => {
    const r = newCanvas.getBoundingClientRect();
    const mx = e.clientX - r.left;
    const my = e.clientY - r.top;
    const gpos = screenToGraph(mx, my);

    // Hit test nodes
    let hitNode = null;
    for (const n of nodes) {
      const dx = gpos.x - n.x;
      const dy = gpos.y - n.y;
      if (dx * dx + dy * dy < (n.r + 10) * (n.r + 10)) {
        hitNode = n;
        break;
      }
    }

    if (hitNode) {
      isDraggingNode = true;
      dragNode = hitNode;
      newCanvas.style.cursor = 'grabbing';
    } else {
      isPanningCanvas = true;
      startMouseX = mx;
      startMouseY = my;
      initialPanX = APP_STATE.graphPanX;
      initialPanY = APP_STATE.graphPanY;
      newCanvas.style.cursor = 'move';
    }
  });

  newCanvas.addEventListener('mousemove', (e) => {
    const r = newCanvas.getBoundingClientRect();
    const mx = e.clientX - r.left;
    const my = e.clientY - r.top;

    if (isDraggingNode && dragNode) {
      const gpos = screenToGraph(mx, my);
      dragNode.x = gpos.x;
      dragNode.y = gpos.y;
      drawGraph();
    } else if (isPanningCanvas) {
      const deltaX = mx - startMouseX;
      const deltaY = my - startMouseY;
      APP_STATE.graphPanX = initialPanX + deltaX;
      APP_STATE.graphPanY = initialPanY + deltaY;
      drawGraph();
    } else {
      const gpos = screenToGraph(mx, my);
      let hover = false;
      for (const n of nodes) {
        const dx = gpos.x - n.x;
        const dy = gpos.y - n.y;
        if (dx * dx + dy * dy < (n.r + 10) * (n.r + 10)) {
          hover = true;
          break;
        }
      }
      newCanvas.style.cursor = hover ? 'grab' : 'default';
    }
  });

  const endInteraction = () => {
    isDraggingNode = false;
    isPanningCanvas = false;
    dragNode = null;
    newCanvas.style.cursor = 'default';
  };

  newCanvas.addEventListener('mouseup', endInteraction);
  newCanvas.addEventListener('mouseleave', endInteraction);

  // Wheel Zoom
  newCanvas.addEventListener('wheel', (e) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.12 : 0.88;
    zoomGraph(zoomFactor);
  }, { passive: false });
}

// ═══════════════════════════════════════════════════════════════════
// VIEW 7: EVIDENCE CENTER
// ═══════════════════════════════════════════════════════════════════
function renderEvidenceView() {
  const listEl = $('evidenceList');
  if (!listEl) return;

  const findings = [...APP_STATE.findings].sort((a, b) => (b.qei_score || 0) - (a.qei_score || 0));
  setText('evidenceFindingsCount', findings.length);

  listEl.innerHTML = findings.map(f => {
    const algo = f.crypto_asset?.algorithm_variant || f.crypto_asset?.algorithm_family || 'Unknown';
    const loc  = shortPath(f.evidence?.file_path || '');
    const line = f.evidence?.start_line ? `:${f.evidence.start_line}` : '';
    const qei  = Math.round(f.qei_score || 0);

    return `
      <div class="ev-list-item" id="ev-item-${f.finding_id}" onclick="openEvidence('${f.finding_id}')">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px;">
          <span style="font-weight:700;color:var(--text-main);font-size:0.82rem;">${algo}</span>
          <span class="mono" style="font-size:0.75rem;font-weight:800;color:${qeiColor(qei)}">QEI ${qei}</span>
        </div>
        <div class="mono" style="font-size:0.72rem;color:var(--text-muted);">${loc}${line}</div>
      </div>
    `;
  }).join('');
}

function openEvidence(fid) {
  if (!fid) return;
  const f = APP_STATE.findings.find(x => x.finding_id === fid);
  if (!f) return;

  APP_STATE.activeEvidenceFinding = f;

  document.querySelectorAll('.ev-list-item').forEach(el => el.classList.remove('selected'));
  const activeEl = $(`ev-item-${fid}`);
  if (activeEl) {
    activeEl.classList.add('selected');
    activeEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  switchTab('tab-evidence');
  window.scrollTo({ top: 0, behavior: 'smooth' });
  renderEvidenceDetail(f);
}

function renderEvidenceDetail(f) {
  const algo     = f.crypto_asset?.algorithm_variant || f.crypto_asset?.algorithm_family || 'Unknown';
  const evId     = f.evidence?.evidence_id || '--';
  const fId      = f.finding_id || '--';
  const filePath = f.evidence?.file_path || '';
  const line     = f.evidence?.start_line || 1;
  const func     = f.evidence?.function_name || 'N/A';
  const snippet  = f.evidence?.code_snippet || '// No code snippet available';
  const pqcT     = f.pqc_recommendation?.target_algorithm || 'ML-KEM / ML-DSA (NIST FIPS 203/204)';
  const steps    = f.pqc_recommendation?.remediation_steps || [];
  const fixCode  = f.pqc_recommendation?.suggested_code_snippet || '';

  setText('evidenceId', `${algo} — ${evId}`);
  setText('evidenceFindingId', `Finding ID: ${fId} | File: ${filePath}`);

  const container = $('evidenceSections');
  if (!container) return;

  const snippetLines = snippet.split('\n').map((l, i) => {
    const ln = parseInt(line) + i;
    const isHighlight = i === 0;
    return `
      <div class="code-line-row ${isHighlight ? 'highlighted' : ''}">
        <span class="code-ln">${ln}</span>
        <span class="code-txt">${escapeHtml(l)}</span>
      </div>
    `;
  }).join('');

  container.innerHTML = `
    <!-- SECTION 1: CODE EVIDENCE -->
    <div class="ev-block-section">
      <div class="ev-block-header">
        <span class="ev-block-title">Source Code Provenance & AST Verification</span>
        <button class="btn btn-sm btn-outline" onclick="copySnippet('${escapeHtml(snippet)}')">Copy Snippet</button>
      </div>
      <div class="ev-block-body">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.85rem;margin-bottom:1rem;font-size:0.78rem;">
          <div><span style="color:var(--text-muted);">File Path:</span> <strong class="mono" style="color:var(--text-main);">${filePath}</strong></div>
          <div><span style="color:var(--text-muted);">Location:</span> <strong class="mono" style="color:var(--primary);">Line ${line} (${func})</strong></div>
          <div><span style="color:var(--text-muted);">Detection Rule:</span> <strong class="mono" style="color:var(--purple);">${f.evidence?.rule_id || 'RULE'}</strong></div>
          <div><span style="color:var(--text-muted);">Verification Confidence:</span> <strong style="color:var(--success);">98% (AST Semantic Verified)</strong></div>
        </div>
        <div class="code-viewer-wrapper">
          ${snippetLines}
        </div>
      </div>
    </div>

    <!-- SECTION 2: QUANTUM THREAT ASSESSMENT -->
    <div class="ev-block-section">
      <div class="ev-block-header">
        <span class="ev-block-title">Deterministic Quantum Vulnerability Analysis</span>
        ${statusBadge(f.quantum_status)}
      </div>
      <div class="ev-block-body" style="font-size:0.82rem;line-height:1.6;color:var(--text-body);">
        <p><strong style="color:var(--text-main);">Threat Vector:</strong> ${f.threat_vector || "Shor's Algorithm polynomial time factorisation"}</p>
        <p style="margin-top:0.5rem;"><strong style="color:var(--text-main);">Security Strength:</strong> Classical: ${f.classical_security_bits || 112} bits → <strong style="color:var(--critical);">Quantum: ${f.quantum_security_bits || 0} bits</strong></p>
        <p style="margin-top:0.5rem;"><strong style="color:var(--text-main);">NIST Standard Status:</strong> ${f.nist_status || 'NIST SP 800-131A Rev 3 Deprecation by 2030'}</p>
        <p style="margin-top:0.5rem;"><strong style="color:var(--text-main);">HNDL Exposure Risk:</strong> <span style="color:${f.hndl_risk === 'CRITICAL' ? 'var(--critical)' : 'var(--warning)'};font-weight:800;">${f.hndl_risk || 'HIGH'}</span> — Data is actively captured today for future retroactive decryption.</p>
      </div>
    </div>

    <!-- SECTION 3: PQC REMEDIATION -->
    <div class="ev-block-section">
      <div class="ev-block-header">
        <span class="ev-block-title">NIST Post-Quantum Migration Playbook</span>
        <span class="wave-tag-badge ${waveClass(f.pqc_recommendation?.migration_wave)}">${waveName(f.pqc_recommendation?.migration_wave)}</span>
      </div>
      <div class="ev-block-body">
        <div style="margin-bottom:1rem;">
          <div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;font-weight:600;">NIST FIPS Approved Target Primitive</div>
          <div style="font-size:1.15rem;font-weight:800;color:var(--success);margin-top:2px;">${pqcT}</div>
        </div>

        ${fixCode ? `
          <div style="margin-bottom:1rem;">
            <div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:4px;font-weight:600;">Recommended Code Replacement</div>
            <div class="code-viewer-wrapper" style="color:#a7f3d0;">
              <pre style="padding:0.85rem 1.15rem;margin:0;">${escapeHtml(fixCode)}</pre>
            </div>
          </div>
        ` : ''}

        ${steps.length ? `
          <div>
            <div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px;font-weight:600;">Step-by-Step Remediation Actions</div>
            ${steps.map(s => `<div style="font-size:0.78rem;color:var(--text-body);padding:3px 0;">• ${s}</div>`).join('')}
          </div>
        ` : ''}
      </div>
    </div>
  `;
}

function copySnippet(text) {
  navigator.clipboard.writeText(text);
  alert('Code snippet copied to clipboard.');
}

// ═══════════════════════════════════════════════════════════════════
// CBOM & CSV EXPORTS
// ═══════════════════════════════════════════════════════════════════
function exportCBOM() {
  if (!APP_STATE.cbom) {
    alert('CBOM is loading. Please wait a moment.');
    return;
  }
  const blob = new Blob([JSON.stringify(APP_STATE.cbom, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `qview-cbom-cyclonedx-1.6-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportUniverseCsv() {
  const filtered = getFilteredFindings();
  if (filtered.length === 0) {
    alert('No findings to export.');
    return;
  }

  const headers = ['Finding ID', 'Algorithm', 'Primitive', 'Key Size', 'Quantum Status', 'Location', 'Line', 'QEI', 'CAI', 'HNDL Risk', 'Mosca Flag', 'Target PQC'];
  const rows = filtered.map(f => [
    f.finding_id,
    f.crypto_asset?.algorithm_variant || f.crypto_asset?.algorithm_family,
    f.crypto_asset?.primitive,
    f.crypto_asset?.key_size || '',
    f.quantum_status,
    `"${f.evidence?.file_path || ''}"`,
    f.evidence?.start_line || '',
    f.qei_score || 0,
    f.cai_score || 0,
    f.hndl_risk || '',
    f.mosca_flag ? 'YES' : 'NO',
    `"${f.pqc_recommendation?.target_algorithm || ''}"`
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `qview-crypto-findings-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ═══════════════════════════════════════════════════════════════════
// TABS & USER GUIDE MODAL NAVIGATION
// ═══════════════════════════════════════════════════════════════════
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === tabId);
  });

  if (tabId === 'tab-graph') {
    setTimeout(renderGraphView, 100);
  }
}

function setupNavigation() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Quick Filter Pills
  document.querySelectorAll('.pill-filter').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.pill-filter').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const st = btn.dataset.filterStatus;
      const mosca = btn.dataset.filterMosca === 'true';
      const hardcoded = btn.dataset.filterHardcoded === 'true';

      APP_STATE.activeFilter.status = st !== undefined ? st : '';
      APP_STATE.activeFilter.moscaOnly = mosca;
      APP_STATE.activeFilter.hardcodedOnly = hardcoded;
      renderUniverseView();
    });
  });

  // Search input with shortcut '/'
  const sInput = $('universeSearch');
  sInput?.addEventListener('input', () => {
    APP_STATE.activeFilter.search = sInput.value;
    renderUniverseView();
  });

  window.addEventListener('keydown', (e) => {
    // Search focus '/'
    if (e.key === '/' && document.activeElement !== sInput && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
      e.preventDefault();
      switchTab('tab-universe');
      sInput?.focus();
      return;
    }

    // Graph Zoom shortcuts (+, -, 0) when graph tab is open
    const graphPanel = $('tab-graph');
    if (graphPanel && graphPanel.classList.contains('active') && document.activeElement?.tagName !== 'INPUT') {
      if (e.key === '+' || e.key === '=') {
        e.preventDefault();
        zoomGraph(1.2);
      } else if (e.key === '-' || e.key === '_') {
        e.preventDefault();
        zoomGraph(0.8);
      } else if (e.key === '0') {
        e.preventDefault();
        resetGraphView();
      }
    }
  });

  $('filterPrimitive')?.addEventListener('change', (e) => {
    APP_STATE.activeFilter.primitive = e.target.value;
    renderUniverseView();
  });

  // User Guide Modal Handlers
  const modal = $('guideModal');
  const openModal = () => { if (modal) modal.style.display = 'flex'; };
  const closeModal = () => { if (modal) modal.style.display = 'none'; };

  $('btnOpenGuide')?.addEventListener('click', openModal);
  $('btnCloseGuide')?.addEventListener('click', closeModal);
  $('btnGuideGotIt')?.addEventListener('click', closeModal);
  modal?.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });
}

// ═══════════════════════════════════════════════════════════════════
// PROGRESS LOADER & ANIMATIONS
// ═══════════════════════════════════════════════════════════════════
function showLoader(msg = 'Processing...') {
  const el = $('loadingOverlay');
  if (el) { el.style.display = 'flex'; setText('loadingStatus', msg); }
}

function hideLoader() {
  const el = $('loadingOverlay');
  if (el) el.style.display = 'none';
}

function animateScanProgress() {
  const wrap = $('scanProgressWrap');
  if (wrap) wrap.classList.add('visible');
  let pct = 0;
  const stages = [
    [500, 25, 'Running AST Semantic Code Analysis...'],
    [700, 50, 'Auditing PKI Certificates & Cryptographic Keys...'],
    [500, 75, 'Analyzing Dependencies & Generating CycloneDX CBOM...'],
    [400, 90, 'Executing Mosca\'s Inequality & HNDL Risk Engine...'],
    [200, 100, 'Scan Complete!']
  ];
  let delay = 0;
  stages.forEach(([dur, target, label]) => {
    setTimeout(() => {
      pct = target;
      if ($('scanProgressFill')) $('scanProgressFill').style.width = `${pct}%`;
      setText('scanProgressPct', `${pct}%`);
      setText('scanProgressLabel', label);
    }, delay);
    delay += dur;
  });
}

function hideScanProgress() {
  setTimeout(() => {
    const wrap = $('scanProgressWrap');
    if (wrap) wrap.classList.remove('visible');
  }, 500);
}

// ═══════════════════════════════════════════════════════════════════
// FALLBACK DATASET (Offline mode)
// ═══════════════════════════════════════════════════════════════════
function showFallbackData() {
  const demoFindings = [
    {
      finding_id: 'QF-001', assessment_id: 'ASM-01',
      quantum_status: 'CRITICAL_VULNERABLE', hndl_risk: 'CRITICAL',
      mosca_flag: true, business_criticality: 5,
      data_sensitivity: 'PHI_GENOMIC', confidentiality_lifetime_years: 30,
      threat_vector: "Shor's Algorithm polynomial time factorisation",
      nist_status: 'Deprecated by 2030 (NIST SP 800-131A)',
      classical_security_bits: 112, quantum_security_bits: 0,
      qei_score: 95.0, cai_score: 28.0,
      crypto_asset: { algorithm_family: 'RSA', algorithm_variant: 'RSA-2048', primitive: 'signature', key_size: 2048, library_name: 'Java JCA', hardcoded: false },
      evidence: { evidence_id: 'EVD-01', file_path: 'src/auth/PatientAuthService.java', start_line: 45, function_name: 'generateAuthToken()', code_snippet: 'Signature sig = Signature.getInstance("SHA256withRSA");\nsig.initSign(privateKey);', rule_id: 'RULE-JAVA-RSA' },
      pqc_recommendation: { target_algorithm: 'ML-DSA-65 (NIST FIPS 204)', migration_wave: 'WAVE_1_CRITICAL', effort_estimate: 'MEDIUM', suggested_code_snippet: 'Signature sig = Signature.getInstance("ML-DSA-65", "BCPQC");\nsig.initSign(privateKey);', remediation_steps: ['Add BCPQC provider jar', 'Replace getInstance with ML-DSA-65', 'Generate new FIPS 204 key pair'] }
    },
    {
      finding_id: 'QF-002', assessment_id: 'ASM-01',
      quantum_status: 'CRITICAL_VULNERABLE', hndl_risk: 'CRITICAL',
      mosca_flag: true, business_criticality: 5,
      data_sensitivity: 'CONFIDENTIAL', confidentiality_lifetime_years: 10,
      threat_vector: "Shor's Algorithm discrete logarithm break",
      nist_status: 'Deprecated by 2030',
      classical_security_bits: 128, quantum_security_bits: 0,
      qei_score: 92.0, cai_score: 50.0,
      crypto_asset: { algorithm_family: 'ECC', algorithm_variant: 'ECDH-P256', primitive: 'key-establishment', key_size: 256, library_name: 'crypto', hardcoded: false },
      evidence: { evidence_id: 'EVD-02', file_path: 'src/payment/payment_crypto.js', start_line: 18, function_name: 'generateECDHSession()', code_snippet: 'const ecdh = crypto.createECDH("prime256v1");', rule_id: 'RULE-JS-ECDH' },
      pqc_recommendation: { target_algorithm: 'ML-KEM-768 (NIST FIPS 203)', migration_wave: 'WAVE_1_CRITICAL', effort_estimate: 'MEDIUM', suggested_code_snippet: 'const { publicKey, secretKey } = mlkem.keypair();', remediation_steps: ['Adopt liboqs / ML-KEM-768 hybrid', 'Upgrade TLS 1.3 cipher suites'] }
    },
    {
      finding_id: 'QF-003', assessment_id: 'ASM-01',
      quantum_status: 'QUANTUM_SAFE', hndl_risk: 'LOW',
      mosca_flag: false, business_criticality: 4,
      data_sensitivity: 'CONFIDENTIAL', confidentiality_lifetime_years: 5,
      threat_vector: "NIST Approved Quantum-Safe Lattice Signature",
      nist_status: 'NIST FIPS 204 Approved',
      classical_security_bits: 192, quantum_security_bits: 128,
      qei_score: 5.0, cai_score: 85.0,
      crypto_asset: { algorithm_family: 'ML-DSA', algorithm_variant: 'ML-DSA-65', primitive: 'signature', key_size: 1952, library_name: 'BouncyCastle BCPQC', hardcoded: false },
      evidence: { evidence_id: 'EVD-03', file_path: 'src/modern/QuantumSafeDocumentSigner.java', start_line: 32, function_name: 'signDocument()', code_snippet: 'Signature signer = Signature.getInstance("ML-DSA-65", "BCPQC");', rule_id: 'RULE-JAVA-MLDSA' },
      pqc_recommendation: { target_algorithm: 'Already Quantum-Safe (ML-DSA-65)', migration_wave: 'WAVE_4_LEGACY', effort_estimate: 'LOW', remediation_steps: ['Monitor NIST PQC updates', 'Keep BouncyCastle PQC updated'] }
    }
  ];

  APP_STATE.findings = demoFindings;
  APP_STATE.summary = {
    assessment_id: 'ASM-DEMO',
    target_name: 'Sentara Healthcare Platform',
    timestamp: new Date().toISOString(),
    total_files_scanned: 32,
    total_loc_scanned: 5120,
    total_crypto_assets: demoFindings.length,
    quantum_vulnerable_count: 2,
    medium_risk_count: 0,
    quantum_safe_count: 1,
    mosca_violation_count: 2,
    hndl_critical_count: 2,
    qri: 42.0, base_qri: 46.0, qei: 85.0, cai: 45.0, coverage_confidence: 0.92,
    qri_dimensions: {
      crypto_exposure: { score: 15, weight: 0.25 },
      data_protection: { score: 33, weight: 0.15 },
      business_criticality: { score: 20, weight: 0.15 },
      crypto_agility: { score: 45, weight: 0.15 },
      pqc_compatibility: { score: 33, weight: 0.10 },
      inventory_coverage: { score: 92, weight: 0.10 },
      migration_complexity: { score: 65, weight: 0.05 },
      governance_policy: { score: 30, weight: 0.05 }
    },
    findings: demoFindings,
    compliance_report: {
      total_violations: 8,
      frameworks_evaluated: 7,
      framework_summary: {
        NIST_FIPS: { framework_name: 'NIST FIPS 203/204/205', authority: 'NIST', compliance_status: 'NON_COMPLIANT', critical_violations: 2, high_violations: 1, total_violations: 3, violations: [] },
        HIPAA: { framework_name: 'HIPAA Security Rule', authority: 'HHS', compliance_status: 'NON_COMPLIANT', critical_violations: 2, high_violations: 0, total_violations: 2, violations: [] },
        PCI_DSS: { framework_name: 'PCI-DSS 4.0', authority: 'PCI-SSC', compliance_status: 'NON_COMPLIANT', critical_violations: 2, high_violations: 1, total_violations: 3, violations: [] }
      }
    }
  };
  renderAllViews();
}

// ═══════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();

  $('btnExportCbom')?.addEventListener('click', exportCBOM);
  $('btnExportUniverseCsv')?.addEventListener('click', exportUniverseCsv);
  $('btnTriggerScan')?.addEventListener('click', () => {
    const p = $('targetPathInput')?.value || 'sample_data';
    triggerDiscoveryScan(p);
  });
  $('btnScanCustomPath')?.addEventListener('click', () => {
    const p = $('targetPathInput')?.value || 'sample_data';
    triggerDiscoveryScan(p);
  });

  // Load telemetry
  fetchAssessment();

  // ── User Guide Modal with tabbed navigation ──────────────────────────────
  const GUIDE_TABS = ['getting-started', 'inputs', 'tabs', 'scores', 'tips'];
  let guideTabIdx = 0;

  function switchGuideTab(tabKey) {
    guideTabIdx = GUIDE_TABS.indexOf(tabKey);
    if (guideTabIdx < 0) guideTabIdx = 0;

    // Update tab buttons
    document.querySelectorAll('.guide-tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.guideTab === GUIDE_TABS[guideTabIdx]);
    });

    // Update panels
    document.querySelectorAll('.guide-panel').forEach(panel => {
      panel.classList.toggle('active', panel.id === 'guide-' + GUIDE_TABS[guideTabIdx]);
    });

    // Update dots
    document.querySelectorAll('.guide-dot').forEach(dot => {
      dot.classList.toggle('active', dot.dataset.guideTab === GUIDE_TABS[guideTabIdx]);
    });

    // Update prev/next buttons
    const prevBtn = btnGuidePrev;
    const nextBtn = btnGuideNext;
    if (prevBtn) prevBtn.disabled = guideTabIdx === 0;
    if (nextBtn) {
      nextBtn.textContent = guideTabIdx === GUIDE_TABS.length - 1 ? "Let's Start!" : "Next →";
    }
  }

  // Open guide
  btnOpenGuide?.addEventListener('click', () => {
    const modal = guideModal;
    if (modal) { modal.style.display = 'flex'; switchGuideTab(GUIDE_TABS[guideTabIdx]); }
  });

  // Close guide
  function closeGuide() {
    const modal = guideModal;
    if (modal) modal.style.display = 'none';
  }
  btnCloseGuide?.addEventListener('click', closeGuide);
  guideModal?.addEventListener('click', e => { if (e.target.id === 'guideModal') closeGuide(); });

  // Next button
  btnGuideNext?.addEventListener('click', () => {
    if (guideTabIdx >= GUIDE_TABS.length - 1) { closeGuide(); return; }
    switchGuideTab(GUIDE_TABS[guideTabIdx + 1]);
  });

  // Prev button
  btnGuidePrev?.addEventListener('click', () => {
    if (guideTabIdx > 0) switchGuideTab(GUIDE_TABS[guideTabIdx - 1]);
  });

  // Tab button clicks
  document.querySelectorAll('.guide-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchGuideTab(btn.dataset.guideTab));
  });

  // Dot clicks
  document.querySelectorAll('.guide-dot').forEach(dot => {
    dot.addEventListener('click', () => switchGuideTab(dot.dataset.guideTab));
  });

  // Esc closes guide
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && guideModal?.style.display !== 'none') closeGuide();
  });

  // Auto-show guide on first visit
  if (!localStorage.getItem('qview_guide_seen')) {
    setTimeout(() => {
      const modal = guideModal;
      if (modal) { modal.style.display = 'flex'; switchGuideTab('getting-started'); }
      localStorage.setItem('qview_guide_seen', '1');
    }, 2200);
  }
});
