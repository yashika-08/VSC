import * as vscode from 'vscode';
import { SentinelCodeLensProvider } from './providers/codeLensProvider';
import { SentinelDiagnosticsProvider } from './providers/diagnosticsProvider';
import { SentinelSidebarProvider } from './providers/sidebarProvider';
import { SentinelIssuesTreeProvider } from './providers/issuesTreeProvider';
import { SentinelOwaspTreeProvider } from './providers/owaspTreeProvider';
import { FixPreviewContentProvider } from './providers/fixPreviewProvider';
import { SecretShieldWorker } from './analysis/secretShield';
import { ScanOrchestrator } from './analysis/scanOrchestrator';
import { StatusBarManager } from './utils/statusBar';

let scanOrchestrator: ScanOrchestrator;
let statusBarManager: StatusBarManager;
let diagnosticsProvider: SentinelDiagnosticsProvider;
let fixPreviewProvider: FixPreviewContentProvider;

export function activate(context: vscode.ExtensionContext) {
  console.log('Sentinel-VSC activated');

  // Core providers
  diagnosticsProvider = new SentinelDiagnosticsProvider();
  const secretShield = new SecretShieldWorker();
  scanOrchestrator = new ScanOrchestrator(diagnosticsProvider, secretShield);
  statusBarManager = new StatusBarManager();

  // Fix preview content provider (for sentinel-fix: URI scheme)
  fixPreviewProvider = new FixPreviewContentProvider();
  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider('sentinel-fix', fixPreviewProvider)
  );

  // Sidebar webview
  const sidebarProvider = new SentinelSidebarProvider(context.extensionUri, scanOrchestrator);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider('sentinel.securityPanel', sidebarProvider)
  );

  // Issues tree
  const issuesTreeProvider = new SentinelIssuesTreeProvider(scanOrchestrator);
  vscode.window.createTreeView('sentinel.issuesTree', {
    treeDataProvider: issuesTreeProvider,
    showCollapseAll: true
  });

  // OWASP coverage tree
  const owaspTreeProvider = new SentinelOwaspTreeProvider(scanOrchestrator);
  vscode.window.createTreeView('sentinel.owaspTree', {
    treeDataProvider: owaspTreeProvider
  });

  // CodeLens provider
  const supportedLangs = vscode.workspace.getConfiguration('sentinel').get<string[]>('supportedLanguages') ?? [];
  const codeLensProvider = new SentinelCodeLensProvider(scanOrchestrator);
  const codeLensDisposable = vscode.languages.registerCodeLensProvider(
    supportedLangs.map(lang => ({ language: lang })),
    codeLensProvider
  );
  context.subscriptions.push(codeLensDisposable);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('sentinel.scanFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      statusBarManager.setScanning();
      try {
        const result = await scanOrchestrator.scanDocument(editor.document);
        statusBarManager.setGrade(result.grade);
        sidebarProvider.updateReport(result);
        issuesTreeProvider.refresh(result.issues);
        owaspTreeProvider.refresh(result.owaspCoverage);
        vscode.window.showInformationMessage(
          `Sentinel: Grade ${result.grade.letter} (${result.grade.score}/100) — ${result.issues.length} issue(s) found`
        );
      } catch (err: any) {
        statusBarManager.setError();
        vscode.window.showErrorMessage(`Sentinel scan failed: ${err.message}`);
      }
    }),

    vscode.commands.registerCommand('sentinel.fixIssue', async (issueId: string) => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const fix = await scanOrchestrator.generateFix(editor.document, issueId);
      if (!fix) {
        vscode.window.showWarningMessage('Sentinel: No fix available for this issue.');
        return;
      }
      const action = await vscode.window.showInformationMessage(
        `Sentinel Fix Ready: ${fix.description}`,
        'Apply Fix', 'Preview', 'Dismiss'
      );
      if (action === 'Apply Fix') {
        const edit = new vscode.WorkspaceEdit();
        edit.replace(editor.document.uri, fix.range, fix.replacement);
        await vscode.workspace.applyEdit(edit);
        vscode.window.showInformationMessage('Sentinel: Fix applied! Re-scanning...');
        vscode.commands.executeCommand('sentinel.scanFile');
      } else if (action === 'Preview') {
        showFixPreviewDiff(editor.document, fix, fixPreviewProvider);
      }
    }),

    vscode.commands.registerCommand('sentinel.revealSecret', async (line: number) => {
      const choice = await vscode.window.showWarningMessage(
        'Revealing this secret may expose sensitive credentials. Are you sure?',
        { modal: true },
        'Reveal Temporarily'
      );
      if (choice === 'Reveal Temporarily') {
        secretShield.temporarilyReveal(line);
        setTimeout(() => secretShield.remask(line), 30000);
      }
    }),

    vscode.commands.registerCommand('sentinel.openPanel', () => {
      vscode.commands.executeCommand('workbench.view.extension.sentinel-sidebar');
    })
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const cfg = vscode.workspace.getConfiguration('sentinel');
      if (!cfg.get('scanOnSave')) return;
      if (!isSupportedLanguage(doc.languageId)) return;
      statusBarManager.setScanning();
      const result = await scanOrchestrator.scanDocument(doc);
      statusBarManager.setGrade(result.grade);
      sidebarProvider.updateReport(result);
      issuesTreeProvider.refresh(result.issues);
    })
  );

  // Auto-scan on type (debounced)
  let typeTimer: NodeJS.Timeout;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const cfg = vscode.workspace.getConfiguration('sentinel');
      if (!cfg.get('scanOnType')) return;
      if (!isSupportedLanguage(event.document.languageId)) return;
      clearTimeout(typeTimer);
      typeTimer = setTimeout(async () => {
        const result = await scanOrchestrator.scanDocument(event.document);
        statusBarManager.setGrade(result.grade);
        codeLensProvider.refresh();
      }, 1500);
    })
  );

  // Secret shield: decorate active editor
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) secretShield.applyDecorations(editor);
    })
  );

  statusBarManager.setReady();
  context.subscriptions.push(statusBarManager);
  context.subscriptions.push(diagnosticsProvider);
  context.subscriptions.push(secretShield);
}

async function showFixPreviewDiff(
  doc: vscode.TextDocument,
  fix: any,
  provider: FixPreviewContentProvider
) {
  // Build the full document text with the fix applied
  const fixedContent = doc.getText().substring(0, doc.offsetAt(fix.range.start))
    + fix.replacement
    + doc.getText().substring(doc.offsetAt(fix.range.end));

  // Store the content in the provider so it can serve it when VS Code requests it
  const fixUri = provider.setFixContent(doc.uri, fix.id, fixedContent);

  // Open the built-in diff editor: original ↔ fixed
  vscode.commands.executeCommand('vscode.diff', doc.uri, fixUri, 'Current ↔ Sentinel Fix');
}

function isSupportedLanguage(languageId: string): boolean {
  const supported = vscode.workspace.getConfiguration('sentinel').get<string[]>('supportedLanguages') ?? [];
  return supported.includes(languageId);
}

export function deactivate() {
  scanOrchestrator?.dispose();
  statusBarManager?.dispose();
  diagnosticsProvider?.dispose();
  fixPreviewProvider?.dispose();
}
