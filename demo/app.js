function pretty(x) {
  try {
    return JSON.stringify(x, null, 2);
  } catch (_) {
    return String(x);
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

async function postForm(url, formEl, outputElId) {
  const out = document.getElementById(outputElId);
  out.textContent = 'Running...';
  const formData = new FormData(formEl);
  try {
    const resp = await fetch(url, {
      method: 'POST',
      body: formData,
    });
    const data = await resp.json();
    out.textContent = pretty(data);
    return data;
  } catch (err) {
    out.textContent = `Request failed: ${err}`;
    return null;
  }
}

document.getElementById('btn-refresh').addEventListener('click', fetchStatus);

document.getElementById('init-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const data = await postForm('/api/init', e.currentTarget, 'init-output');
  if (data && data.ok) {
    await fetchStatus();
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

  const formData = new FormData(e.currentTarget);
  try {
    const resp = await fetch('/api/process', {
      method: 'POST',
      body: formData,
    });
    const data = await resp.json();
    if (!data.ok) {
      resultBox.textContent = pretty(data);
      traceBox.textContent = 'No trace';
      llmBox.textContent = pretty(data.llm_calls || []);
      return;
    }

    resultBox.textContent = pretty(data.outcome.result);
    traceBox.textContent = pretty(data.outcome.trace);
    llmBox.textContent = pretty(data.llm_calls || []);
    await fetchStatus();
  } catch (err) {
    resultBox.textContent = `Request failed: ${err}`;
    traceBox.textContent = 'No trace';
    llmBox.textContent = 'No llm calls';
  }
});

fetchStatus();
