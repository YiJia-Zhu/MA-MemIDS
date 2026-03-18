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

async function loadGraphNoteDetail(formEl) {
  const out = document.getElementById('graph-note-detail');
  out.textContent = 'Loading...';
  const formData = new FormData(formEl);
  const noteId = String(formData.get('note_id') || '').trim();
  if (!noteId) {
    out.textContent = 'Please input note_id';
    return;
  }

  try {
    const resp = await fetch(`/api/graph/note/${encodeURIComponent(noteId)}`);
    const data = await resp.json();
    out.textContent = pretty(data);
  } catch (err) {
    out.textContent = `Load note detail failed: ${err}`;
  }
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
      await fetchStatus();
      await fetchGraphSummary();
      const listBox = document.getElementById('graph-list');
      listBox.textContent = 'Graph cleared. Click Load Notes to refresh list.';
      const detailBox = document.getElementById('graph-note-detail');
      detailBox.textContent = '';
    }
  } catch (err) {
    out.textContent = `Clear graph failed: ${err}`;
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
  } catch (err) {
    resultBox.textContent = `Process failed: ${err}`;
    traceBox.textContent = 'No trace';
    llmBox.textContent = 'No llm calls';
  }
});

fetchStatus();
fetchGraphSummary();
