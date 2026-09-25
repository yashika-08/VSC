import * as vscode from 'vscode';

export function getSidebarHtml(_webview: vscode.Webview, _extensionUri: vscode.Uri): string {
  const nonce = getNonce();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel Security</title>
  <style nonce="${nonce}">
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-sideBar-background);
      padding: 0;
      overflow-x: hidden;
    }
    .section { padding: 10px 12px; border-bottom: 1px solid var(--vscode-panel-border); }
    .section-title {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--vscode-foreground);
      opacity: 0.7;
      margin-bottom: 8px;
    }
    .grade-row {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
    }
    .grade-circle {
      width: 56px;
      height: 56px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      font-weight: 700;
      flex-shrink: 0;
      border: 3px solid;
    }
    .grade-A { color: #3fb950; border-color: #3fb950; }
    .grade-B { color: #58a6ff; border-color: #58a6ff; }
    .grade-C { color: #d29922; border-color: #d29922; }
    .grade-D { color: #db6d28; border-color: #db6d28; }
    .grade-F { color: #f85149; border-color: #f85149; }
    .grade-meta { flex: 1; }
    .grade-score { font-size: 18px; font-weight: 600; }
    .grade-desc { font-size: 11px; opacity: 0.7; margin-top: 2px; }
    .score-bars { display: flex; flex-direction: column; gap: 5px; }
    .score-row { display: flex; align-items: center; gap: 6px; font-size: 11px; }
    .score-label { width: 80px; opacity: 0.8; }
    .score-track { flex: 1; height: 4px; background: var(--vscode-scrollbarSlider-background); border-radius: 2px; overflow: hidden; }
    .score-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease; }
    .score-val { width: 24px; text-align: right; font-size: 11px; }
    .issues-section { max-height: 300px; overflow-y: auto; }
    .issue-item {
      padding: 7px 12px;
      border-bottom: 1px solid var(--vscode-panel-border);
      cursor: pointer;
      transition: background 0.1s;
    }
    .issue-item:hover { background: var(--vscode-list-hoverBackground); }
    .issue-header { display: flex; align-items: center; gap: 6px; margin-bottom: 2px; }
    .severity-badge {
      font-size: 10px;
      padding: 1px 5px;
      border-radius: 3px;
      font-weight: 600;
    }
    .sev-critical { background: rgba(248,81,73,0.2); color: #f85149; }
    .sev-warning { background: rgba(210,153,34,0.2); color: #d29922; }
    .sev-info { background: rgba(88,166,255,0.15); color: #58a6ff; }
    .owasp-label { font-size: 10px; opacity: 0.6; margin-left: auto; font-family: monospace; }
    .issue-title { font-size: 12px; font-weight: 500; }
    .issue-line { font-size: 10px; opacity: 0.6; margin-top: 2px; font-family: monospace; }
    .action-btn {
      width: 100%;
      padding: 6px;
      margin-top: 6px;
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      border-radius: 3px;
      cursor: pointer;
      font-size: 12px;
      font-family: var(--vscode-font-family);
    }
    .action-btn:hover { background: var(--vscode-button-hoverBackground); }
    .action-btn.secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
    .scanning-state { padding: 16px; text-align: center; opacity: 0.7; }
    .no-issues { padding: 16px; text-align: center; color: #3fb950; }
    .empty-state { padding: 20px 12px; text-align: center; opacity: 0.6; }
    .stats-row { display: flex; gap: 8px; margin-bottom: 10px; }
    .stat-card {
      flex: 1;
      background: var(--vscode-editorWidget-background);
      border: 1px solid var(--vscode-panel-border);
      border-radius: 4px;
      padding: 6px 8px;
      text-align: center;
    }
    .stat-val { font-size: 16px; font-weight: 600; }
    .stat-label { font-size: 10px; opacity: 0.7; margin-top: 1px; }
  </style>
</head>
<body>
  <div id="app">
    <div class="empty-state">
      <div style="font-size:20px;margin-bottom:8px">🛡</div>
      <div style="font-size:12px;font-weight:500;margin-bottom:6px">Sentinel-VSC Ready</div>
      <div style="font-size:11px">Save a file or click Scan to analyze your code.</div>
      <button class="action-btn" style="margin-top:12px" onclick="sendMsg('scanFile')">▶ Scan Current File</button>
    </div>
  </div>

<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();

  function sendMsg(command, data) {
    vscode.postMessage({ command, ...data });
  }

  window.addEventListener('message', e => {
    const msg = e.data;
    if (msg.command === 'updateReport') renderReport(msg.data);
    if (msg.command === 'setScanning') renderScanning();
  });

  function renderScanning() {
    document.getElementById('app').innerHTML = \`
      <div class="scanning-state">
        <div style="font-size:20px;margin-bottom:8px">🔍</div>
        <div style="font-size:12px">Sentinel scanning...</div>
        <div style="font-size:11px;opacity:0.6;margin-top:4px">Running SAST + LLM Critic</div>
      </div>\`;
  }

  function renderReport(result) {
    const g = result.grade;
    const issues = result.issues;
    const criticals = issues.filter(i => i.severity === 'critical').length;
    const warnings = issues.filter(i => i.severity === 'warning').length;
    const infos = issues.filter(i => i.severity === 'info').length;

    const gradeColors = { A:'#3fb950', B:'#58a6ff', C:'#d29922', D:'#db6d28', F:'#f85149' };
    const color = gradeColors[g.letter] || '#8b949e';

    const issuesHtml = issues.length === 0
      ? '<div class="no-issues">✓ No vulnerabilities found!</div>'
      : issues.map(issue => \`
        <div class="issue-item" onclick="sendMsg('goToLine', {line: \${issue.line}})">
          <div class="issue-header">
            <span class="severity-badge sev-\${issue.severity}">\${issue.severity.toUpperCase()}</span>
            <span class="owasp-label">\${issue.owaspCategory}</span>
          </div>
          <div class="issue-title">\${escHtml(issue.title)}</div>
          <div class="issue-line">Line \${issue.line} · \${escHtml(issue.source.toUpperCase())}</div>
          \${issue.fix ? \`<button class="action-btn secondary" style="margin-top:4px;font-size:11px" onclick="event.stopPropagation();sendMsg('fixIssue', {issueId:'\${issue.id}'})">🔧 Fix with Sentinel</button>\` : ''}
        </div>\`).join('');

    document.getElementById('app').innerHTML = \`
      <div class="section">
        <div class="section-title">Security Grade</div>
        <div class="grade-row">
          <div class="grade-circle grade-\${g.letter}">\${g.letter}</div>
          <div class="grade-meta">
            <div class="grade-score" style="color:\${color}">\${g.score} / 100</div>
            <div class="grade-desc">\${escHtml(g.description)}</div>
            <div style="font-size:10px;opacity:0.6;margin-top:3px">\${result.linesScanned} lines · \${result.language}</div>
          </div>
        </div>
        <div class="stats-row">
          <div class="stat-card">
            <div class="stat-val" style="color:#f85149">\${criticals}</div>
            <div class="stat-label">Critical</div>
          </div>
          <div class="stat-card">
            <div class="stat-val" style="color:#d29922">\${warnings}</div>
            <div class="stat-label">Warning</div>
          </div>
          <div class="stat-card">
            <div class="stat-val" style="color:#58a6ff">\${infos}</div>
            <div class="stat-label">Info</div>
          </div>
        </div>
        <button class="action-btn" onclick="sendMsg('scanFile')">↻ Re-scan File</button>
      </div>
      <div class="section">
        <div class="section-title">Vulnerabilities (\${issues.length})</div>
        <div class="issues-section">\${issuesHtml}</div>
      </div>\`;
  }

  function escHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
</script>
</body>
</html>`;
}

function getNonce(): string {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
