import * as vscode from 'vscode';

/**
 * Provides virtual document content for the `sentinel-fix:` URI scheme.
 * Used to power the "Preview" button in the fix flow, which shows a
 * diff view between the current document and the proposed fix.
 */
export class FixPreviewContentProvider implements vscode.TextDocumentContentProvider {
  private fixContents = new Map<string, string>();
  private _onDidChange = new vscode.EventEmitter<vscode.Uri>();

  readonly onDidChange = this._onDidChange.event;

  /**
   * Build a stable map key from a URI.
   * `uri.toString()` can vary depending on how the URI was constructed
   * (encoding differences, trailing slashes, etc.). Using path + query
   * gives a consistent, normalised key.
   */
  private uriKey(uri: vscode.Uri): string {
    return `${uri.path}?${uri.query}`;
  }

  /**
   * Store the fixed version of a document so the diff viewer can retrieve it.
   * @param originalUri The original document URI
   * @param fixId A unique identifier for this fix
   * @param content The full text of the document with the fix applied
   */
  setFixContent(originalUri: vscode.Uri, fixId: string, content: string): vscode.Uri {
    const fixUri = vscode.Uri.parse(
      `sentinel-fix:${originalUri.fsPath}?fix=${encodeURIComponent(fixId)}`
    );
    this.fixContents.set(this.uriKey(fixUri), content);
    this._onDidChange.fire(fixUri);
    return fixUri;
  }

  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.fixContents.get(this.uriKey(uri))
      ?? '// Fix content not available — try running the fix again.';
  }

  clearFix(fixId: string) {
    const encoded = encodeURIComponent(fixId);
    for (const [key] of this.fixContents) {
      if (key.includes(`fix=${encoded}`) || key.includes(`fix=${fixId}`)) {
        this.fixContents.delete(key);
      }
    }
  }

  dispose() {
    this._onDidChange.dispose();
    this.fixContents.clear();
  }
}

