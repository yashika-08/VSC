import * as vscode from 'vscode';
import { ScanOrchestrator } from '../analysis/scanOrchestrator';
import { ScanResult } from '../utils/types';
import { getSidebarHtml } from '../webview/sidebarHtml';

export class SentinelSidebarProvider implements vscode.WebviewViewProvider {
  private view?: vscode.WebviewView;
  private lastResult?: ScanResult;

  constructor(
    private readonly extensionUri: vscode.Uri,
    private readonly orchestrator: ScanOrchestrator
  ) {
    this.orchestrator.onScanComplete((result) => {
      this.lastResult = result;
      this.updateReport(result);
    });
  }

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this.view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [
        vscode.Uri.joinPath(this.extensionUri, 'webview')
      ]
    };

    webviewView.webview.html = getSidebarHtml(webviewView.webview, this.extensionUri);

    // Handle messages from webview
    webviewView.webview.onDidReceiveMessage(async (msg) => {
      switch (msg.command) {
        case 'scanFile':
          await vscode.commands.executeCommand('sentinel.scanFile');
          break;
        case 'fixIssue':
          await vscode.commands.executeCommand('sentinel.fixIssue', msg.issueId);
          break;
        case 'openSettings':
          vscode.commands.executeCommand('workbench.action.openSettings', 'sentinel');
          break;
        case 'goToLine': {
          const editor = vscode.window.activeTextEditor;
          if (editor && msg.line) {
            const pos = new vscode.Position(msg.line - 1, 0);
            editor.selection = new vscode.Selection(pos, pos);
            editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
            vscode.window.showTextDocument(editor.document);
          }
          break;
        }
        case 'copyFix':
          if (msg.fix) vscode.env.clipboard.writeText(msg.fix);
          break;
      }
    });

    // Send last result if available
    if (this.lastResult) {
      this.updateReport(this.lastResult);
    }
  }

  updateReport(result: ScanResult) {
    if (!this.view) return;
    this.view.webview.postMessage({
      command: 'updateReport',
      data: result
    });
  }

  setScanning() {
    if (!this.view) return;
    this.view.webview.postMessage({ command: 'setScanning' });
  }
}
