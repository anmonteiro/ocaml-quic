const RESULTS_PATH = './benchmarks/results.jsonl';
const REPO_URL = 'https://github.com/anmonteiro/ocaml-quic';
const SCENARIOS = {
  h3_upload_curl: { label: 'Upload', color: '#0057b8' },
  h3_download_curl: { label: 'Download', color: '#c05621' },
};

function formatNumber(value, digits = 2) {
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(value);
}

function formatDate(value) {
  return new Date(value).toLocaleString('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }) + ' UTC';
}

function parseJsonLines(text) {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function groupByCommit(records) {
  const map = new Map();
  records.forEach((record) => {
    const key = record.commit_sha;
    if (!map.has(key)) {
      map.set(key, {
        commit_sha: record.commit_sha,
        commit_short: record.commit_short,
        timestamp_utc: record.timestamp_utc,
        branch: record.branch,
        runner_os: record.runner_os || '-',
        runner_arch: record.runner_arch || '-',
        workflow_url: record.workflow_url || '',
        scenarios: {},
      });
    }
    const entry = map.get(key);
    if (record.timestamp_utc > entry.timestamp_utc) {
      entry.timestamp_utc = record.timestamp_utc;
      entry.workflow_url = record.workflow_url || entry.workflow_url;
    }
    entry.scenarios[record.scenario] = record;
  });
  return Array.from(map.values()).sort((a, b) => new Date(a.timestamp_utc) - new Date(b.timestamp_utc));
}

function renderSummary(commits, rawRecords) {
  const latest = commits.at(-1);
  document.getElementById('dataset-commits').textContent = `${commits.length}`;
  document.getElementById('dataset-runs').textContent = `${rawRecords.length} scenario runs`;
  if (!latest) return;

  const latestUpload = latest.scenarios.h3_upload_curl;
  const latestDownload = latest.scenarios.h3_download_curl;

  document.getElementById('latest-upload-throughput').textContent = latestUpload
    ? `${formatNumber(latestUpload.median_mib_per_s)} MiB/s`
    : '-';
  document.getElementById('latest-upload-total').textContent = latestUpload
    ? `${formatNumber(latestUpload.median_total_s, 3)} s median`
    : '-';

  document.getElementById('latest-download-throughput').textContent = latestDownload
    ? `${formatNumber(latestDownload.median_mib_per_s)} MiB/s`
    : '-';
  document.getElementById('latest-download-total').textContent = latestDownload
    ? `${formatNumber(latestDownload.median_total_s, 3)} s median`
    : '-';
}

function renderChart(commits) {
  const labels = commits.map((entry) => entry.commit_short);
  const datasets = Object.entries(SCENARIOS).map(([scenario, meta]) => ({
    label: meta.label,
    data: commits.map((entry) => entry.scenarios[scenario]?.median_mib_per_s ?? null),
    borderColor: meta.color,
    backgroundColor: meta.color,
    tension: 0.2,
    spanGaps: true,
  }));

  new Chart(document.getElementById('throughput-chart'), {
    type: 'line',
    data: { labels, datasets },
    options: {
      maintainAspectRatio: false,
      scales: {
        y: {
          title: { display: true, text: 'MiB/s' },
        },
        x: {
          ticks: { maxRotation: 65, minRotation: 65 },
        },
      },
      plugins: {
        tooltip: {
          callbacks: {
            afterBody(items) {
              const idx = items[0].dataIndex;
              const entry = commits[idx];
              return formatDate(entry.timestamp_utc);
            },
          },
        },
      },
    },
  });
}

function renderTable(commits) {
  const tbody = document.getElementById('results-body');
  if (commits.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8">No benchmark data yet.</td></tr>';
    return;
  }

  tbody.innerHTML = commits
    .slice()
    .reverse()
    .map((entry) => {
      const upload = entry.scenarios.h3_upload_curl;
      const download = entry.scenarios.h3_download_curl;
      const commitUrl = `${REPO_URL}/commit/${entry.commit_sha}`;
      const runLink = entry.workflow_url
        ? `<a class="badge" href="${entry.workflow_url}">workflow</a>`
        : '-';
      return `
        <tr>
          <td>${formatDate(entry.timestamp_utc)}</td>
          <td><a href="${commitUrl}"><code>${entry.commit_short}</code></a></td>
          <td>${upload ? formatNumber(upload.median_mib_per_s) : '-'}</td>
          <td>${upload ? formatNumber(upload.median_total_s, 3) : '-'}</td>
          <td>${download ? formatNumber(download.median_mib_per_s) : '-'}</td>
          <td>${download ? formatNumber(download.median_total_s, 3) : '-'}</td>
          <td>${entry.runner_os || '-'} ${entry.runner_arch || ''}</td>
          <td>${runLink}</td>
        </tr>`;
    })
    .join('');
}

async function main() {
  const response = await fetch(RESULTS_PATH, { cache: 'no-store' });
  if (!response.ok) throw new Error(`Failed to fetch ${RESULTS_PATH}: ${response.status}`);
  const text = await response.text();
  const records = parseJsonLines(text);
  const commits = groupByCommit(records);
  renderSummary(commits, records);
  renderChart(commits);
  renderTable(commits);
}

main().catch((error) => {
  document.getElementById('results-body').innerHTML = `<tr><td colspan="8">${error.message}</td></tr>`;
  console.error(error);
});
