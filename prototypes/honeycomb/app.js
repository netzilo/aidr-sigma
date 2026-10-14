const LEVELS = [
  { name: 'Teams', child: 'providers' },
  { name: 'AI Providers', child: 'models' },
  { name: 'Models', child: null },
];
const RANGE_MULT = { 'Last 24 hours': 1 / 30, 'Last 7 days': 7 / 30, 'Last 30 days': 1 };
const METRIC_LABEL = { tokens: 'Tokens', events: 'Events', detections: 'Detections', rate: 'Detection rate' };

// Dark-surface sequential ramps: low end recedes into the surface, high end is brightest.
const RAMP_RISK = ['#2a2326', '#5c262b', '#9a2d34', '#d23f45', '#ff6f6a', '#ffb3ab'];
const RAMP_VOLUME = ['#18212e', '#104281', '#1c5cab', '#2a78d6', '#5598e7', '#9ec5f4'];

const state = {
  path: [AIDR_DATA],
  selected: null,
  mode: 'activity',
  colorBy: 'rate',
  labelBy: 'tokens',
  range: 'Last 30 days',
};

const fmtSI = d3.format('.3~s');
const fmtInt = d3.format(',');
const fmtPct = d3.format('.2%');
const current = () => state.path[state.path.length - 1];
const depth = () => state.path.length - 1;

function value(d, metric) {
  if (metric === 'rate') return d.events ? d.detections / d.events : 0;
  if (metric === 'users') return d.users;
  return d[metric] * RANGE_MULT[state.range];
}
function fmt(metric, v) {
  if (metric === 'rate') return fmtPct(v);
  return fmtSI(Math.round(v)).replace('G', 'B');
}
function topDetector(d) {
  return DETECTORS.reduce((a, b) => (d.byType[b.key] > d.byType[a.key] ? b : a));
}
function inkFor(fill) {
  return d3.lab(fill).l > 62 ? '#0b0f15' : '#e6edf5';
}

// ── Hex geometry (pointy-top, axial coords, spiral from center) ──────────────
const SQ3 = Math.sqrt(3);
const AXIAL_DIRS = [[1, 0], [1, -1], [0, -1], [-1, 0], [-1, 1], [0, 1]];

function spiral(n) {
  const out = [[0, 0]];
  for (let ring = 1; out.length < n; ring++) {
    let q = -ring, r = ring;
    for (let side = 0; side < 6; side++) {
      for (let step = 0; step < ring; step++) {
        out.push([q, r]);
        q += AXIAL_DIRS[side][0];
        r += AXIAL_DIRS[side][1];
      }
    }
  }
  return out.slice(0, n);
}

function hexPath(size) {
  const pts = d3.range(6).map(i => {
    const a = (Math.PI / 180) * (60 * i - 30);
    return [size * Math.cos(a), size * Math.sin(a)];
  });
  return 'M' + pts.map(p => p.join(',')).join('L') + 'Z';
}

function layout(items, W, H) {
  const coords = spiral(items.length);
  const unit = coords.map(([q, r]) => [SQ3 * (q + r / 2), 1.5 * r]);
  const xs = unit.map(p => p[0]), ys = unit.map(p => p[1]);
  const spanX = d3.max(xs) - d3.min(xs) + SQ3;
  const spanY = d3.max(ys) - d3.min(ys) + 2;
  const size = Math.min(150, (W * 0.86) / spanX, (H * 0.84) / spanY);
  const cx = (d3.max(xs) + d3.min(xs)) / 2, cy = (d3.max(ys) + d3.min(ys)) / 2;
  return {
    size,
    cells: items.map((d, i) => ({ d, x: W / 2 + (unit[i][0] - cx) * size, y: H / 2 + (unit[i][1] - cy) * size })),
  };
}

// ── SVG scaffold ─────────────────────────────────────────────────────────────
const svg = d3.select('#hive');
const root = svg.append('g');
let layer = root.append('g');
const tooltip = document.getElementById('tooltip');
let lastOrigin = null;

svg.on('click', e => { if (e.target === svg.node()) goUp(); });

function stageSize() {
  const el = document.getElementById('canvas-wrap');
  return [el.clientWidth, el.clientHeight];
}

function colorScale(items) {
  const metric = state.colorBy;
  const ramp = metric === 'tokens' || metric === 'events' ? RAMP_VOLUME : RAMP_RISK;
  const max = d3.max(items, d => value(d, metric)) || 1;
  const t = metric === 'rate' ? d3.scaleLinear([0, max], [0, 1]) : d3.scaleSqrt([0, max], [0, 1]);
  const interp = d3.interpolateRgbBasis(ramp);
  const fn = d => interp(0.08 + 0.92 * t(value(d, metric)));
  fn.max = max;
  fn.ramp = ramp;
  return fn;
}

// ── Render ───────────────────────────────────────────────────────────────────
function render(transition = null) {
  const node = current();
  const items = [...node.children].sort((a, b) => value(b, state.labelBy) - value(a, state.labelBy));
  const [W, H] = stageSize();
  const { size, cells } = layout(items, W, H);
  const color = colorScale(items);
  const leaf = depth() === LEVELS.length - 1;

  const old = layer;
  layer = root.append('g');

  const g = layer.selectAll('g.cell').data(cells, c => c.d.id).join('g')
    .attr('class', c => 'cell' + (leaf ? ' leaf' : '') + (state.mode === 'detections' && !c.d.detections ? ' dim' : ''))
    .attr('tabindex', 0)
    .attr('role', 'button')
    .attr('aria-label', c => `${c.d.name}: ${fmt(state.labelBy, value(c.d, state.labelBy))} ${METRIC_LABEL[state.labelBy]}`)
    .on('click', (e, c) => { e.stopPropagation(); activate(c); })
    .on('keydown', (e, c) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(c); } })
    .on('mousemove', (e, c) => showTip(e, c.d))
    .on('mouseleave', hideTip)
    .on('focus', function (e, c) { const b = this.getBoundingClientRect(); showTip({ clientX: b.right, clientY: b.top + b.height / 2 }, c.d); })
    .on('blur', hideTip);

  const inner = size - 2;
  g.append('path').attr('class', 'hex').attr('d', hexPath(inner))
    .attr('fill', c => color(c.d)).attr('stroke', '#0b0f15').attr('stroke-width', 2);
  g.filter(c => c.d.sanctioned === false || (c.d.type === 'team' && c.d.children.some(p => !p.sanctioned)))
    .append('path').attr('class', 'shadow-ring').attr('d', hexPath(inner - 6))
    .attr('opacity', c => (c.d.type === 'team' ? 0.55 : 1));
  g.filter(c => state.selected && c.d.id === state.selected.id)
    .append('path').attr('d', hexPath(inner + 1)).attr('fill', 'none').attr('stroke', '#fff').attr('stroke-width', 3);

  g.each(function (c) { drawLabel(d3.select(this), c.d, inner, color(c.d)); });

  // Transitions: drill-in grows children out of the clicked cell; drill-out collapses back.
  const from = transition && transition.origin;
  if (transition && transition.dir === 'in') {
    old.transition().duration(260).attr('opacity', 0).remove();
    g.attr('transform', `translate(${from.x},${from.y}) scale(0.15)`).attr('opacity', 0)
      .transition().delay((_, i) => 120 + i * 28).duration(420).ease(d3.easeCubicOut)
      .attr('transform', c => `translate(${c.x},${c.y})`).attr('opacity', 1);
  } else if (transition && transition.dir === 'out') {
    old.transition().duration(260).attr('opacity', 0)
      .attr('transform', `translate(${from ? from.x : W / 2},${from ? from.y : H / 2}) scale(0.2)`).remove();
    g.attr('transform', c => `translate(${c.x},${c.y}) scale(0.85)`).attr('opacity', 0)
      .transition().delay((_, i) => 80 + i * 18).duration(360).ease(d3.easeCubicOut)
      .attr('transform', c => `translate(${c.x},${c.y})`).attr('opacity', 1);
  } else {
    old.remove();
    g.attr('transform', c => `translate(${c.x},${c.y})`);
  }

  renderChrome(node, items, color);
}

function drawLabel(sel, d, size, fill) {
  const ink = inkFor(fill);
  const nameSize = Math.max(10, Math.min(16, size * 0.17));
  const valSize = Math.max(12, Math.min(24, size * 0.26));
  const subSize = Math.max(9, Math.min(12, size * 0.12));
  const maxChars = Math.floor((size * 1.5) / (nameSize * 0.56));
  const name = d.name.length > maxChars ? d.name.slice(0, maxChars - 1) + '…' : d.name;
  const sub = d.children ? `${d.children.length} ${LEVELS[depth()].child}` : `${fmtInt(d.users)} users`;
  const showSub = size > 46;

  sel.append('text').attr('text-anchor', 'middle').attr('y', -valSize * 0.55)
    .attr('fill', ink).attr('font-size', nameSize).attr('font-weight', 600).text(name);
  sel.append('text').attr('text-anchor', 'middle').attr('y', valSize * 0.5)
    .attr('fill', ink).attr('font-size', valSize).attr('font-weight', 700)
    .attr('style', 'font-variant-numeric: tabular-nums')
    .text(fmt(state.labelBy, value(d, state.labelBy)));
  if (showSub) {
    sel.append('text').attr('text-anchor', 'middle').attr('y', valSize * 0.5 + subSize + 6)
      .attr('fill', ink).attr('opacity', 0.75).attr('font-size', subSize).text(sub);
  }
}

// ── Navigation ───────────────────────────────────────────────────────────────
function activate(c) {
  hideTip();
  if (c.d.children) {
    lastOrigin = { x: c.x, y: c.y };
    state.path.push(c.d);
    state.selected = null;
    render({ dir: 'in', origin: lastOrigin });
  } else {
    state.selected = state.selected && state.selected.id === c.d.id ? null : c.d;
    render();
  }
}

function goTo(index) {
  if (index >= depth()) return;
  state.path = state.path.slice(0, index + 1);
  state.selected = null;
  render({ dir: 'out', origin: lastOrigin });
  lastOrigin = null;
}
function goUp() { if (depth() > 0) goTo(depth() - 1); }

document.addEventListener('keydown', e => {
  if ((e.key === 'Escape' || e.key === 'Backspace') && e.target.tagName !== 'SELECT') goUp();
});

// ── Chrome: breadcrumbs, KPIs, legend, panel ─────────────────────────────────
function renderChrome(node, items, color) {
  const lvl = LEVELS[depth()];

  const crumbs = d3.select('#crumbs').selectAll('li').data(state.path, d => d.id).join('li').html('');
  crumbs.each(function (d, i) {
    const li = d3.select(this);
    if (i === depth()) {
      li.append('span').attr('class', 'cur').text(d.name);
      li.append('span').attr('class', 'lvl').text(lvl.name);
    } else {
      li.append('button').text(d.name).on('click', () => goTo(i));
    }
  });

  d3.select('#level-pill').text(`${lvl.name} · ${items.length}`);
  d3.select('#hint').text(lvl.child
    ? `Click a cell to drill into ${lvl.child} · Esc to go back`
    : 'Click a model for details · Esc to go back');

  const shadowCount = node.type === 'root'
    ? new Set(node.children.flatMap(t => t.children.filter(p => !p.sanctioned).map(p => p.key))).size
    : node.type === 'team' ? node.children.filter(p => !p.sanctioned).length
    : (node.sanctioned ? 0 : node.children.length);
  const kpis = [
    ['Tokens', fmt('tokens', value(node, 'tokens'))],
    ['Events', fmt('events', value(node, 'events'))],
    ['Detections', fmt('detections', value(node, 'detections')), 'bad'],
    ['Detection rate', fmt('rate', value(node, 'rate'))],
    ['Users', fmtInt(node.users)],
    [node.type === 'provider' ? 'Unsanctioned models' : 'Shadow AI providers', shadowCount, shadowCount ? 'shadow' : ''],
  ];
  d3.select('#kpis').selectAll('.kpi').data(kpis).join('div').attr('class', 'kpi')
    .html(([k, v, cls]) => `<div class="kpi-label">${k}</div><div class="kpi-value ${cls || ''}">${v}</div>`);

  d3.select('#legend').html(`
    <div class="legend-title">Color · ${METRIC_LABEL[state.colorBy]}</div>
    <div class="legend-bar" style="background:linear-gradient(90deg,${color.ramp.slice(1).join(',')})"></div>
    <div class="legend-scale"><span>0</span><span>${fmt(state.colorBy, color.max)}</span></div>
    <div class="legend-shadow">
      <svg width="16" height="16" viewBox="-9 -9 18 18"><path d="${hexPath(7)}" fill="none" stroke="#c084fc" stroke-width="1.5" stroke-dasharray="3 2"/></svg>
      Unsanctioned (shadow AI)
    </div>`);

  renderPanel(state.selected || node, items, color);
}

function renderPanel(d, items, color) {
  const isLeafDetail = d.type === 'model';
  const typeLabel = { root: 'Organization', team: 'Team', provider: 'AI provider', model: 'Model' }[d.type];
  const context = d.type === 'provider' ? `${d.team} team`
    : d.type === 'model' ? `${d.provider} · ${d.team} team`
    : d.type === 'team' ? `${fmtInt(d.users)} users` : `${d.children.length} teams`;
  const tag = d.sanctioned === false ? '<span class="tag shadow">Shadow AI</span>'
    : d.sanctioned === true ? '<span class="tag ok">Sanctioned</span>' : '';

  const maxType = d3.max(DETECTORS, t => d.byType[t.key]) || 1;
  const bars = DETECTORS
    .map(t => ({ ...t, n: d.byType[t.key] * RANGE_MULT[state.range] }))
    .sort((a, b) => b.n - a.n)
    .map(t => `<div class="bar-row"><span class="lbl">${t.label}</span>
      <span class="track"><span class="fill" style="width:${(100 * t.n) / (maxType * RANGE_MULT[state.range])}%"></span></span>
      <span class="num">${fmt('detections', t.n)}</span></div>`).join('');

  const ranked = isLeafDetail ? [] : [...items].sort((a, b) => value(b, 'detections') - value(a, 'detections')).slice(0, 6);
  const rankHtml = ranked.map(c => `<li data-id="${c.id}"><span class="sw" style="background:${color(c)}"></span>
      <span>${c.name}${c.sanctioned === false ? ' <span class="tag shadow">Shadow</span>' : ''}</span>
      <span class="num">${fmt('detections', value(c, 'detections'))}</span></li>`).join('');

  const panel = d3.select('#panel').html(`
    <div class="p-eyebrow">${typeLabel}</div>
    <div class="p-title">${d.name}${tag}</div>
    <div class="p-sub">${context} · ${state.range.toLowerCase()}</div>
    <div class="p-grid">
      <div><div class="k">Tokens</div><div class="v">${fmt('tokens', value(d, 'tokens'))}</div></div>
      <div><div class="k">Events</div><div class="v">${fmt('events', value(d, 'events'))}</div></div>
      <div><div class="k">Detections</div><div class="v bad">${fmt('detections', value(d, 'detections'))}</div></div>
      <div><div class="k">Detection rate</div><div class="v">${fmt('rate', value(d, 'rate'))}</div></div>
    </div>
    <div class="p-section">Detections by type</div>
    ${bars}
    ${ranked.length ? `<div class="p-section">Top ${LEVELS[depth()].name.toLowerCase()} by detections</div><ul class="rank">${rankHtml}</ul>` : ''}
    <div class="p-actions">
      <span class="btn primary">View matching events</span>
      ${isLeafDetail ? '<span class="btn">Create policy</span>' : ''}
    </div>`);

  panel.selectAll('.rank li').on('click', function () {
    const id = this.dataset.id;
    const [W, H] = stageSize();
    const cell = layout([...current().children].sort((a, b) => value(b, state.labelBy) - value(a, state.labelBy)), W, H)
      .cells.find(c => c.d.id === id);
    if (cell) activate(cell);
  });
}

// ── Tooltip ──────────────────────────────────────────────────────────────────
function showTip(e, d) {
  const top = topDetector(d);
  const lvl = LEVELS[depth()];
  tooltip.innerHTML = `
    <div class="tt-h">${d.name}${d.sanctioned === false ? ' <span class="tag shadow">Shadow AI</span>' : ''}</div>
    <div class="tt-r">Tokens <b>${fmt('tokens', value(d, 'tokens'))}</b></div>
    <div class="tt-r">Events <b>${fmt('events', value(d, 'events'))}</b></div>
    <div class="tt-r">Detections <b>${fmt('detections', value(d, 'detections'))}</b></div>
    <div class="tt-r">Detection rate <b>${fmt('rate', value(d, 'rate'))}</b></div>
    <div class="tt-r">Users <b>${fmtInt(d.users)}</b></div>
    ${d.detections ? `<div class="tt-r">Top detector <b>${top.label}</b></div>` : ''}
    <div class="tt-foot">${lvl.child ? `Click to see ${d.children.length} ${lvl.child} →` : 'Click to pin details'}</div>`;
  const pad = 16, w = tooltip.offsetWidth, h = tooltip.offsetHeight;
  let x = e.clientX + pad, y = e.clientY - h / 2;
  if (x + w > window.innerWidth - 8) x = e.clientX - w - pad;
  y = Math.max(8, Math.min(y, window.innerHeight - h - 8));
  tooltip.style.left = x + 'px';
  tooltip.style.top = y + 'px';
  tooltip.classList.add('on');
}
function hideTip() { tooltip.classList.remove('on'); }

// ── Controls ─────────────────────────────────────────────────────────────────
d3.select('#color-by').on('change', function () { state.colorBy = this.value; render(); });
d3.select('#label-by').on('change', function () { state.labelBy = this.value; render(); });
d3.select('#range').on('change', function () { state.range = this.value; render(); });
d3.selectAll('#mode-seg button').on('click', function () {
  state.mode = this.dataset.mode;
  d3.selectAll('#mode-seg button').classed('on', function () { return this.dataset.mode === state.mode; });
  if (state.mode === 'detections') { state.colorBy = 'detections'; d3.select('#color-by').property('value', 'detections'); }
  render();
});

let resizeTimer;
window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => render(), 120); });

render();
