import * as vscode from 'vscode';
import { SecurityIssue } from '../utils/types';

interface SecretPattern {
  name: string;
  pattern: RegExp;
  description: string;
  owaspCategory: string;
  severity: 'critical' | 'warning';
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: 'AWS Access Key ID detected. Rotate immediately.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'AWS Secret Key',
    pattern: /(?:aws.?secret|secret.?access.?key)['":\s=]+[A-Za-z0-9/+=]{40}/gi,
    description: 'AWS Secret Access Key detected.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'Stripe Live Secret Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    description: 'Stripe live secret key — immediate financial risk.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'Stripe Test Key',
    pattern: /sk_test_[0-9a-zA-Z]{24,}/g,
    description: 'Stripe test key — should still not be committed.',
    owaspCategory: 'A02',
    severity: 'warning'
  },
  {
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[A-Za-z0-9]{36}/g,
    description: 'GitHub PAT — allows full repo/org access.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'GitHub OAuth Token',
    pattern: /gho_[A-Za-z0-9]{36}/g,
    description: 'GitHub OAuth token detected.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'Slack Bot Token',
    pattern: /xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}/g,
    description: 'Slack bot token — allows sending messages as the bot.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'Slack Webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    description: 'Slack incoming webhook — allows posting to channel.',
    owaspCategory: 'A02',
    severity: 'warning'
  },
  {
    name: 'Generic API Key',
    pattern: /(?:api.?key|apikey|api_token)['":\s=]+['"`]([A-Za-z0-9_-]{20,})['"`]/gi,
    description: 'Generic API key hardcoded in source.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'JWT Secret',
    pattern: /(?:jwt.?secret|token.?secret)['":\s=]+['"`]([A-Za-z0-9_\-!@#$%^&*]{12,})['"`]/gi,
    description: 'JWT signing secret — compromise means forging any auth token.',
    owaspCategory: 'A07',
    severity: 'critical'
  },
  {
    name: 'Database Password',
    pattern: /(?:db.?pass(?:word)?|database.?password|mysql.?password|postgres.?password)['":\s=]+['"`]([^'"`\s]{6,})['"`]/gi,
    description: 'Database password hardcoded — use environment variables.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'Database Connection String',
    pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@[^/\s]+/gi,
    description: 'Full database connection string with credentials.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'Private Key (PEM)',
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    description: 'Private key material in source code.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    description: 'Google API key — may allow unauthorized API usage.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'Twilio API Key',
    pattern: /SK[0-9a-fA-F]{32}/g,
    description: 'Twilio API key detected.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  // PII patterns
  {
    name: 'Social Security Number',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    description: 'US Social Security Number (PII) detected in source.',
    owaspCategory: 'A02',
    severity: 'critical'
  },
  {
    name: 'Credit Card Number',
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b/g,
    description: 'Credit card number (PCI DSS violation) detected.',
    owaspCategory: 'A02',
    severity: 'critical'
  }
];

export class SecretShieldWorker {
  private maskedDecorations: vscode.TextEditorDecorationType;
  private revealedLines = new Set<number>();
  private secretsByDocument = new Map<string, Map<number, string>>();

  constructor() {
    this.maskedDecorations = vscode.window.createTextEditorDecorationType({
      color: 'transparent',
      backgroundColor: new vscode.ThemeColor('editorWarning.background'),
      before: {
        contentText: '●●●●●●●●●●●●●●●●',
        color: new vscode.ThemeColor('editorWarning.foreground'),
        backgroundColor: new vscode.ThemeColor('editorWarning.background'),
        border: '1px solid',
        borderColor: new vscode.ThemeColor('editorWarning.border'),
        fontStyle: 'normal',
        fontWeight: '600'
      }
    });
  }

  async scan(doc: vscode.TextDocument): Promise<SecurityIssue[]> {
    const cfg = vscode.workspace.getConfiguration('sentinel');
    if (!cfg.get('maskSecrets')) return [];

    const code = doc.getText();
    const lines = code.split('\n');
    const issues: SecurityIssue[] = [];
    const docSecrets = new Map<number, string>();

    for (const secretPattern of SECRET_PATTERNS) {
      secretPattern.pattern.lastIndex = 0;

      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx];
        secretPattern.pattern.lastIndex = 0;
        const match = secretPattern.pattern.exec(line);

        if (!match) continue;

        docSecrets.set(lineIdx, match[0]);

        issues.push({
          id: `secret-${secretPattern.name}-L${lineIdx + 1}-${Date.now()}`,
          ruleId: `secret-${secretPattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          title: `${secretPattern.name} Detected`,
          description: secretPattern.description,
          severity: secretPattern.severity,
          owaspCategory: secretPattern.owaspCategory,
          line: lineIdx + 1,
          column: match.index,
          matchedText: '●●●●●●●●●●●●●●●●',
          source: 'secret-shield',
          fix: `Move to environment variable:\n${line.split('=')[0].trim()} = process.env.${secretPattern.name.toUpperCase().replace(/\s+/g, '_')}`
        });
      }
    }

    this.secretsByDocument.set(doc.uri.toString(), docSecrets);
    this.applyDecorations(vscode.window.activeTextEditor);

    return issues;
  }

  applyDecorations(editor: vscode.TextEditor | undefined) {
    if (!editor) return;
    const secrets = this.secretsByDocument.get(editor.document.uri.toString());
    if (!secrets) return;

    const decorationRanges: vscode.DecorationOptions[] = [];

    for (const [lineIdx, secretValue] of secrets) {
      if (this.revealedLines.has(lineIdx)) continue;

      const line = editor.document.lineAt(lineIdx);
      const secretStart = line.text.indexOf(secretValue);
      if (secretStart === -1) continue;

      decorationRanges.push({
        range: new vscode.Range(
          new vscode.Position(lineIdx, secretStart),
          new vscode.Position(lineIdx, secretStart + secretValue.length)
        ),
        hoverMessage: new vscode.MarkdownString(
          `**🔑 Sentinel Secret Shield**\n\nSecret masked by Sentinel. [Reveal temporarily](command:sentinel.revealSecret?${encodeURIComponent(JSON.stringify(lineIdx))})`
        )
      });
    }

    editor.setDecorations(this.maskedDecorations, decorationRanges);
  }

  temporarilyReveal(line: number) {
    this.revealedLines.add(line);
    this.applyDecorations(vscode.window.activeTextEditor);
  }

  remask(line: number) {
    this.revealedLines.delete(line);
    this.applyDecorations(vscode.window.activeTextEditor);
  }

  dispose() {
    this.maskedDecorations.dispose();
  }
}
