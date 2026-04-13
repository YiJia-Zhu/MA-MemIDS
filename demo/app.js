const SVG_NS = 'http://www.w3.org/2000/svg';

const GRAPH_NODE_COLORS = {
  rule: '#0f766e',
  traffic: '#b45309',
  default: '#64748b',
  selected: '#111827',
  center: '#be123c',
};

const GRAPH_EDGE_COLORS = {
  tactic_group: '#2563eb',
  semantic_similar: '#ca8a04',
  subsume: '#7c3aed',
  exploit_chain: '#dc2626',
  l_strengthen: '#b45309',
  related: '#64748b',
};

const graphState = {
  data: null,
  selectedNodeId: '',
};

function pretty(x) {
  try {
    return JSON.stringify(x, null, 2);
  } catch (_) {
    return String(x);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function createSvgEl(tag) {
  return document.createElementNS(SVG_NS, tag);
}

function hashString(value) {
  let h = 0;
  const text = String(value || '');
  for (let i = 0; i < text.length; i += 1) {
    h = (h * 31 + text.charCodeAt(i)) >>> 0;
  }
  return h;
}

function edgeColorForType(type) {
  return GRAPH_EDGE_COLORS[type] || GRAPH_EDGE_COLORS.related;
}

function computeEdgeStrokeWidth(weight, extent) {
  const value = Number(weight || 0);
  const minWeight = Number(extent && extent.min);
  const maxWeight = Number(extent && extent.max);

  if (!Number.isFinite(value)) {
    return 2.2;
  }
  if (!Number.isFinite(minWeight) || !Number.isFinite(maxWeight) || maxWeight <= minWeight) {
    return 2.4 + value * 3.2;
  }

  const normalized = (value - minWeight) / (maxWeight - minWeight);
  return 1.8 + normalized * 5.2;
}

function nodeFillColor(node, isSelected) {
  if (isSelected) {
    return GRAPH_NODE_COLORS.selected;
  }
  if (node.is_center) {
    return GRAPH_NODE_COLORS.center;
  }
  return GRAPH_NODE_COLORS[node.note_type] || GRAPH_NODE_COLORS.default;
}

function clearEvents(containerId) {
  const root = document.getElementById(containerId);
  root.innerHTML = '';
  root.dataset.renderedCount = '0';
}

function appendEvents(containerId, events) {
  const root = document.getElementById(containerId);
  const renderedCount = Number(root.dataset.renderedCount || '0');
  if (renderedCount > events.length) {
    root.innerHTML = '';
    root.dataset.renderedCount = '0';
  }

  for (let i = Number(root.dataset.renderedCount || '0'); i < events.length; i += 1) {
    const ev = events[i];
    const item = document.createElement('details');
    item.className = 'event-item';
    item.open = ev.type !== 'progress';

    const summary = document.createElement('summary');
    summary.textContent = `[${ev.at}] ${ev.type} · ${ev.message}`;
    item.appendChild(summary);

    const payload = document.createElement('pre');
    payload.textContent = pretty(ev.payload || {});
    item.appendChild(payload);
    root.appendChild(item);
  }

  root.dataset.renderedCount = String(events.length);
  root.scrollTop = root.scrollHeight;
}

function setAllFoldBlocks(expand) {
  const blocks = document.querySelectorAll('.fold-block');
  blocks.forEach((el) => {
    el.open = expand;
  });
}

function setGraphCanvasMessage(message) {
  const root = document.getElementById('graph-viz');
  root.innerHTML = '';
  const box = document.createElement('div');
  box.className = 'graph-empty';
  box.textContent = message;
  root.appendChild(box);
}

function renderChipRow(containerId, items) {
  const root = document.getElementById(containerId);
  root.innerHTML = '';
  items.forEach((item) => {
    const chip = document.createElement('span');
    chip.className = 'graph-chip';
    if (item.color) {
      const dot = document.createElement('span');
      dot.className = 'graph-dot';
      dot.style.background = item.color;
      chip.appendChild(dot);
    }
    const text = document.createElement('span');
    text.textContent = item.label;
    chip.appendChild(text);
    root.appendChild(chip);
  });
}

function renderGraphMeta(payload) {
  if (!payload || !payload.graph) {
    renderChipRow('graph-viz-meta', [{ label: 'graph unavailable' }]);
    return;
  }

  const stats = payload.graph.stats || {};
  const filters = payload.filters || {};
  const chips = [
    { label: `mode=${payload.graph.mode || 'filtered'}` },
    { label: `nodes=${stats.rendered_nodes || 0}` },
    { label: `edges=${stats.rendered_edges || 0}` },
    { label: `matching=${stats.matching_notes || 0}` },
    { label: `type=${filters.note_type || 'all'}` },
  ];

  if (filters.q) {
    chips.push({ label: `q=${filters.q}` });
  }
  if (filters.note_id) {
    chips.push({ label: `focus=${filters.note_id}` });
  }
  if (stats.truncated) {
    chips.push({ label: 'truncated=yes' });
  }

  renderChipRow('graph-viz-meta', chips);
}

function renderGraphLegend(payload) {
  const stats = payload && payload.graph ? payload.graph.stats || {} : {};
  const linkTypeCounts = stats.link_type_counts || {};
  const items = [
    { label: 'rule note', color: GRAPH_NODE_COLORS.rule },
    { label: 'selected', color: GRAPH_NODE_COLORS.selected },
    { label: 'center', color: GRAPH_NODE_COLORS.center },
  ];

  Object.keys(linkTypeCounts)
    .sort()
    .forEach((type) => {
      items.push({ label: `${type} (${linkTypeCounts[type]})`, color: edgeColorForType(type) });
    });

  renderChipRow('graph-viz-legend', items);
}

function syncGraphFocusInput(noteId) {
  const graphInput = document.getElementById('graph-viz-note-id');
  if (graphInput) {
    graphInput.value = noteId || '';
  }
}

function syncGraphDetailInput(noteId) {
  const detailInput = document.querySelector('#graph-note-form input[name="note_id"]');
  if (detailInput) {
    detailInput.value = noteId || '';
  }
}

async function fetchStatus() {
  const line = document.getElementById('status-line');
  const box = document.getElementById('status-json');
  line.textContent = 'Checking...';
  try {
    const resp = await fetch('/api/status');
    const data = await resp.json();
    line.textContent = data.ok ? 'Backend ready' : 'Backend error';
    box.textContent = pretty(data);
  } catch (err) {
    line.textContent = 'Backend unreachable';
    box.textContent = String(err);
  }
}

async function fetchGraphSummary() {
  const out = document.getElementById('graph-summary');
  out.textContent = 'Loading...';
  try {
    const resp = await fetch('/api/graph/summary');
    const data = await resp.json();
    out.textContent = pretty(data);
  } catch (err) {
    out.textContent = `Load summary failed: ${err}`;
  }
}

async function loadGraphNotes(formEl) {
  const out = document.getElementById('graph-list');
  out.textContent = 'Loading...';

  const params = new URLSearchParams(new FormData(formEl));
  try {
    const resp = await fetch(`/api/graph/notes?${params.toString()}`);
    const data = await resp.json();
    out.textContent = pretty(data);
  } catch (err) {
    out.textContent = `Load notes failed: ${err}`;
  }
}

async function loadGraphNoteDetailById(noteId, options = {}) {
  const out = document.getElementById('graph-note-detail');
  const normalizedId = String(noteId || '').trim();
  if (!normalizedId) {
    out.textContent = 'Please input note_id';
    return null;
  }

  out.textContent = 'Loading...';
  try {
    const resp = await fetch(`/api/graph/note/${encodeURIComponent(normalizedId)}`);
    const data = await resp.json();
    if (!resp.ok || !data.ok) {
      throw new Error(data.error || `HTTP ${resp.status}`);
    }
    out.textContent = pretty(data);
    graphState.selectedNodeId = normalizedId;
    if (options.syncInputs !== false) {
      syncGraphFocusInput(normalizedId);
      syncGraphDetailInput(normalizedId);
    }
    if (graphState.data) {
      renderKnowledgeGraph(graphState.data);
    }
    return data;
  } catch (err) {
    out.textContent = `Load note detail failed: ${err}`;
    return null;
  }
}

async function loadGraphNoteDetail(formEl) {
  const formData = new FormData(formEl);
  const noteId = String(formData.get('note_id') || '').trim();
  return loadGraphNoteDetailById(noteId);
}

async function clearGraph(formEl) {
  const out = document.getElementById('graph-clear-result');
  out.textContent = 'Running...';
  const formData = new FormData(formEl);
  const confirm = String(formData.get('confirm') || '').trim();

  if (!confirm) {
    out.textContent = 'Please input CLEAR first';
    return;
  }
  if (confirm.toUpperCase() !== 'CLEAR') {
    out.textContent = 'Confirmation mismatch: input must be CLEAR';
    return;
  }

  try {
    const resp = await fetch('/api/graph/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm }),
    });
    const data = await resp.json();
    out.textContent = pretty(data);
    if (data.ok) {
      graphState.data = null;
      graphState.selectedNodeId = '';
      await fetchStatus();
      await fetchGraphSummary();
      setGraphCanvasMessage('Graph cleared. Click Render Graph to refresh view.');
      const listBox = document.getElementById('graph-list');
      listBox.textContent = 'Graph cleared. Click Load Notes to refresh list.';
      const detailBox = document.getElementById('graph-note-detail');
      detailBox.textContent = '';
      renderGraphMeta(null);
      renderGraphLegend(null);
      syncGraphFocusInput('');
      syncGraphDetailInput('');
    }
  } catch (err) {
    out.textContent = `Clear graph failed: ${err}`;
  }
}

function estimateGraphHeight(nodeCount) {
  const dynamic = 360 + nodeCount * 10;
  return clamp(dynamic, 400, 620);
}

function initializeGraphNodes(rawNodes, width, height) {
  const cx = width / 2;
  const cy = height / 2;
  const nodes = rawNodes.map((node) => ({
    ...node,
    x: cx,
    y: cy,
    vx: 0,
    vy: 0,
  }));

  const others = nodes.filter((node) => !node.is_center);
  const centerNode = nodes.find((node) => node.is_center);
  if (centerNode) {
    centerNode.x = cx;
    centerNode.y = cy;
  }

  const orbit = Math.max(100, Math.min(width, height) * 0.32);
  others.forEach((node, index) => {
    const angleBase = (Math.PI * 2 * index) / Math.max(others.length, 1);
    const jitter = ((hashString(node.id) % 100) / 100 - 0.5) * 0.6;
    const radiusScale = 0.82 + ((hashString(`${node.id}:r`) % 30) / 100);
    node.x = cx + Math.cos(angleBase + jitter) * orbit * radiusScale;
    node.y = cy + Math.sin(angleBase + jitter) * orbit * radiusScale;
  });

  return nodes;
}

function simulateGraphLayout(rawNodes, rawEdges, width, height) {
  const nodes = initializeGraphNodes(rawNodes, width, height);
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const padding = 32;
  const iterations = nodes.length > 120 ? 70 : 110;
  const repulsion = nodes.length > 120 ? 2600 : 3600;
  const cx = width / 2;
  const cy = height / 2;

  for (let iter = 0; iter < iterations; iter += 1) {
    for (let i = 0; i < nodes.length; i += 1) {
      for (let j = i + 1; j < nodes.length; j += 1) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let dist2 = dx * dx + dy * dy;
        if (dist2 < 1) {
          dist2 = 1;
          dx = (i % 2 === 0 ? 1 : -1) * 0.5;
          dy = (j % 2 === 0 ? -1 : 1) * 0.5;
        }
        const dist = Math.sqrt(dist2);
        const force = repulsion / dist2;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx -= fx;
        a.vy -= fy;
        b.vx += fx;
        b.vy += fy;
      }
    }

    rawEdges.forEach((edge) => {
      const a = nodeMap.get(edge.source);
      const b = nodeMap.get(edge.target);
      if (!a || !b) {
        return;
      }
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const desired = 85 + (1 - Number(edge.weight || 0)) * 90;
      const spring = (dist - desired) * 0.018;
      const fx = (dx / dist) * spring;
      const fy = (dy / dist) * spring;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    });

    nodes.forEach((node) => {
      if (node.is_center) {
        node.x = cx;
        node.y = cy;
        node.vx = 0;
        node.vy = 0;
        return;
      }

      node.vx += (cx - node.x) * 0.0035;
      node.vy += (cy - node.y) * 0.0035;
      node.vx *= 0.84;
      node.vy *= 0.84;
      node.x = clamp(node.x + node.vx, padding, width - padding);
      node.y = clamp(node.y + node.vy, padding, height - padding);
    });
  }

  return nodes;
}

function renderKnowledgeGraph(payload) {
  renderGraphMeta(payload);
  renderGraphLegend(payload);

  const root = document.getElementById('graph-viz');
  root.innerHTML = '';

  if (!payload || !payload.graph) {
    setGraphCanvasMessage('Graph unavailable');
    return;
  }

  const graph = payload.graph;
  const rawNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const rawEdges = Array.isArray(graph.edges) ? graph.edges : [];
  if (!rawNodes.length) {
    setGraphCanvasMessage('No notes matched the current filters');
    return;
  }

  const width = Math.max(root.clientWidth || 720, 320);
  const height = estimateGraphHeight(rawNodes.length);
  root.style.height = `${height}px`;

  const nodes = simulateGraphLayout(rawNodes, rawEdges, width, height);
  const nodeMap = new Map(nodes.map((node) => [node.id, node]));
  const edgeWeights = rawEdges
    .map((edge) => Number(edge.weight))
    .filter((value) => Number.isFinite(value));
  const edgeWeightExtent = edgeWeights.length
    ? { min: Math.min(...edgeWeights), max: Math.max(...edgeWeights) }
    : null;

  const svg = createSvgEl('svg');
  svg.classList.add('graph-svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('aria-label', 'Note knowledge graph');

  const edgeLayer = createSvgEl('g');
  const edgeLabelLayer = createSvgEl('g');
  const nodeLayer = createSvgEl('g');

  rawEdges.forEach((edge) => {
    const source = nodeMap.get(edge.source);
    const target = nodeMap.get(edge.target);
    if (!source || !target) {
      return;
    }

    const line = createSvgEl('line');
    line.setAttribute('x1', String(source.x));
    line.setAttribute('y1', String(source.y));
    line.setAttribute('x2', String(target.x));
    line.setAttribute('y2', String(target.y));
    line.setAttribute('stroke', edgeColorForType(edge.link_type));
    line.setAttribute('stroke-width', String(computeEdgeStrokeWidth(edge.weight, edgeWeightExtent)));
    line.setAttribute('stroke-opacity', '0.72');
    const title = createSvgEl('title');
    title.textContent = `${edge.link_type} · w=${Number(edge.weight || 0).toFixed(4)}`;
    line.appendChild(title);
    edgeLayer.appendChild(line);

    if (rawEdges.length <= 16) {
      const edgeLabel = createSvgEl('text');
      edgeLabel.setAttribute('x', String((source.x + target.x) / 2));
      edgeLabel.setAttribute('y', String((source.y + target.y) / 2 - 4));
      edgeLabel.setAttribute('text-anchor', 'middle');
      edgeLabel.setAttribute('fill', edgeColorForType(edge.link_type));
      edgeLabel.setAttribute('font-family', 'IBM Plex Mono, monospace');
      edgeLabel.setAttribute('font-size', '10');
      edgeLabel.textContent = `${edge.link_type} · ${Number(edge.weight || 0).toFixed(2)}`;
      edgeLabelLayer.appendChild(edgeLabel);
    }
  });

  nodes.forEach((node) => {
    const isSelected = node.id === graphState.selectedNodeId;
    const group = createSvgEl('g');
    group.style.cursor = 'pointer';

    if (isSelected || node.is_center) {
      const halo = createSvgEl('circle');
      halo.setAttribute('cx', String(node.x));
      halo.setAttribute('cy', String(node.y));
      halo.setAttribute('r', String(Number(node.radius || 12) + 8));
      halo.setAttribute('fill', isSelected ? 'rgba(17, 24, 39, 0.10)' : 'rgba(190, 18, 60, 0.12)');
      group.appendChild(halo);
    }

    const circle = createSvgEl('circle');
    circle.setAttribute('cx', String(node.x));
    circle.setAttribute('cy', String(node.y));
    circle.setAttribute('r', String(node.radius || 12));
    circle.setAttribute('fill', nodeFillColor(node, isSelected));
    circle.setAttribute('stroke', '#fffaf0');
    circle.setAttribute('stroke-width', isSelected ? '3' : '2');
    group.appendChild(circle);

    const label = createSvgEl('text');
    label.setAttribute('x', String(node.x));
    label.setAttribute('y', String(node.y - (node.radius || 12) - 10));
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('fill', '#1f2937');
    label.setAttribute('font-family', 'IBM Plex Mono, monospace');
    label.setAttribute('font-size', node.is_center ? '12' : '11');
    label.setAttribute('font-weight', '600');
    label.textContent = node.label;
    group.appendChild(label);

    const subtitle = createSvgEl('text');
    subtitle.setAttribute('x', String(node.x));
    subtitle.setAttribute('y', String(node.y + (node.radius || 12) + 16));
    subtitle.setAttribute('text-anchor', 'middle');
    subtitle.setAttribute('fill', '#526071');
    subtitle.setAttribute('font-family', 'IBM Plex Mono, monospace');
    subtitle.setAttribute('font-size', '10');
    subtitle.textContent = node.subtitle;
    group.appendChild(subtitle);

    group.addEventListener('click', async () => {
      graphState.selectedNodeId = node.id;
      syncGraphFocusInput(node.id);
      syncGraphDetailInput(node.id);
      renderKnowledgeGraph(graphState.data);
      await loadGraphNoteDetailById(node.id, { syncInputs: false });
    });

    nodeLayer.appendChild(group);
  });

  svg.appendChild(edgeLayer);
  svg.appendChild(edgeLabelLayer);
  svg.appendChild(nodeLayer);
  root.appendChild(svg);
}

async function fetchGraphView(formEl) {
  setGraphCanvasMessage('Loading graph...');
  const params = new URLSearchParams(new FormData(formEl));

  try {
    const resp = await fetch(`/api/graph/view?${params.toString()}`);
    const data = await resp.json();
    if (!resp.ok || !data.ok) {
      throw new Error(data.error || `HTTP ${resp.status}`);
    }
    graphState.data = data;
    if (data.filters && data.filters.note_id) {
      graphState.selectedNodeId = data.filters.note_id;
    } else if (
      graphState.selectedNodeId &&
      !((data.graph && data.graph.nodes) || []).some((node) => node.id === graphState.selectedNodeId)
    ) {
      graphState.selectedNodeId = '';
    }
    renderKnowledgeGraph(data);
  } catch (err) {
    graphState.data = null;
    renderGraphMeta(null);
    renderGraphLegend(null);
    setGraphCanvasMessage(`Load graph failed: ${err}`);
  }
}

async function runAsyncJob({
  startUrl,
  formEl,
  submitBtnId,
  liveContainerId,
  liveStatusId,
}) {
  const submitBtn = document.getElementById(submitBtnId);
  const liveStatus = document.getElementById(liveStatusId);

  clearEvents(liveContainerId);
  submitBtn.disabled = true;
  liveStatus.textContent = 'Submitting...';

  const formData = new FormData(formEl);
  const startedAt = Date.now();
  let jobId = '';

  try {
    const resp = await fetch(startUrl, {
      method: 'POST',
      body: formData,
    });
    const data = await resp.json();
    if (!data.ok) {
      throw new Error(data.error || 'Failed to create async job');
    }
    jobId = data.job_id;
  } catch (err) {
    liveStatus.textContent = `Start failed: ${err}`;
    submitBtn.disabled = false;
    throw err;
  }

  while (true) {
    let jobData;
    try {
      const jobResp = await fetch(`/api/job/${jobId}`);
      jobData = await jobResp.json();
      if (!jobData.ok) {
        throw new Error(jobData.error || 'job fetch failed');
      }
    } catch (err) {
      liveStatus.textContent = `Polling failed: ${err}`;
      submitBtn.disabled = false;
      throw err;
    }

    const job = jobData.job;
    const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
    appendEvents(liveContainerId, job.events || []);
    liveStatus.textContent = `Job ${job.job_id} · ${job.status} · ${elapsed}s · events=${(job.events || []).length}`;

    if (job.status === 'succeeded') {
      submitBtn.disabled = false;
      return job.result;
    }
    if (job.status === 'failed') {
      submitBtn.disabled = false;
      throw new Error(job.error || 'job failed');
    }

    await sleep(1000);
  }
}

document.getElementById('btn-refresh').addEventListener('click', fetchStatus);
document.getElementById('btn-graph-summary').addEventListener('click', fetchGraphSummary);
document.getElementById('btn-expand-all').addEventListener('click', () => setAllFoldBlocks(true));
document.getElementById('btn-collapse-all').addEventListener('click', () => setAllFoldBlocks(false));

document.getElementById('graph-viz-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  await fetchGraphView(e.currentTarget);
});

document.getElementById('btn-graph-reset-focus').addEventListener('click', async () => {
  graphState.selectedNodeId = '';
  syncGraphFocusInput('');
  await fetchGraphView(document.getElementById('graph-viz-form'));
});

document.getElementById('graph-list-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  await loadGraphNotes(e.currentTarget);
});

document.getElementById('graph-note-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  await loadGraphNoteDetail(e.currentTarget);
});

document.getElementById('graph-clear-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  await clearGraph(e.currentTarget);
});

document.getElementById('init-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const output = document.getElementById('init-output');
  output.textContent = 'Running...';
  try {
    const data = await runAsyncJob({
      startUrl: '/api/init_async',
      formEl: e.currentTarget,
      submitBtnId: 'init-submit',
      liveContainerId: 'init-live',
      liveStatusId: 'init-live-status',
    });
    output.textContent = pretty(data);
    await fetchStatus();
    await fetchGraphSummary();
    await fetchGraphView(document.getElementById('graph-viz-form'));
  } catch (err) {
    output.textContent = `Init failed: ${err}`;
  }
});

document.getElementById('process-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const resultBox = document.getElementById('process-result');
  const traceBox = document.getElementById('process-trace');
  const llmBox = document.getElementById('llm-calls');

  resultBox.textContent = 'Running...';
  traceBox.textContent = 'Running...';
  llmBox.textContent = 'Running...';

  try {
    const data = await runAsyncJob({
      startUrl: '/api/process_async',
      formEl: e.currentTarget,
      submitBtnId: 'process-submit',
      liveContainerId: 'process-live',
      liveStatusId: 'process-live-status',
    });

    if (!data.ok) {
      resultBox.textContent = pretty(data);
      traceBox.textContent = 'No trace';
      llmBox.textContent = pretty(data.llm_calls || []);
      return;
    }

    resultBox.textContent = pretty({
      result: data.outcome.result,
      sandbox_config: data.sandbox_config || {},
    });
    traceBox.textContent = pretty(data.outcome.trace);
    llmBox.textContent = pretty(data.llm_calls || []);
    await fetchStatus();
    await fetchGraphSummary();
    await fetchGraphView(document.getElementById('graph-viz-form'));
  } catch (err) {
    resultBox.textContent = `Process failed: ${err}`;
    traceBox.textContent = 'No trace';
    llmBox.textContent = 'No llm calls';
  }
});

let resizeTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (graphState.data) {
      renderKnowledgeGraph(graphState.data);
    }
  }, 140);
});

async function bootstrapPage() {
  await fetchStatus();
  await fetchGraphSummary();
  await fetchGraphView(document.getElementById('graph-viz-form'));
}

bootstrapPage();
