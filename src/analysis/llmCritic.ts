import * as vscode from 'vscode';
import { SecurityIssue, FixSuggestion } from '../utils/types';

interface LLMIssue {
  line: number;
  title: string;
  description: string;
  severity: 'critical' | 'warning' | 'info';
  owaspCategory: string;
  fix: string;
}

interface LLMAnalysisResponse {
  issues: LLMIssue[];
  summary: string;
  overallRisk: string;
}

export class LLMSecurityCritic {
  private static readonly DEFAULT_MODEL = 'claude-sonnet-4-20250514';
  private readonly MAX_CODE_LENGTH = 8000;

  /**
   * Read the model ID from user settings, falling back to the default.
   * This avoids a hardcoded string that silently breaks when deprecated.
   */
  private getModel(): string {
    const config = vscode.workspace.getConfiguration('sentinel');
    return config.get<string>('llmModel') || LLMSecurityCritic.DEFAULT_MODEL;
  }

  private async getApiKey(): Promise<string> {
    const config = vscode.workspace.getConfiguration('sentinel');
    const key = config.get<string>('anthropicApiKey');
    if (!key) {
      const action = await vscode.window.showWarningMessage(
        'Sentinel: No Anthropic API key configured. The LLM Security Critic requires an API key to analyze code.',
        'Open Settings',
        'Continue without LLM'
      );
      if (action === 'Open Settings') {
        vscode.commands.executeCommand(
          'workbench.action.openSettings',
          'sentinel.anthropicApiKey'
        );
      }
      throw new Error('Anthropic API key not configured');
    }
    return key;
  }

  async analyze(
    code: string,
    language: string,
    existingSastIssues: SecurityIssue[]
  ): Promise<SecurityIssue[]> {
    const apiKey = await this.getApiKey();
    const truncatedCode = code.length > this.MAX_CODE_LENGTH
      ? code.substring(0, this.MAX_CODE_LENGTH) + '\n// [truncated for analysis]'
      : code;

    const existingContext = existingSastIssues.length > 0
      ? `\nSAST already found these issues:\n${existingSastIssues.map(i => `- Line ${i.line}: ${i.title}`).join('\n')}\nFocus on finding ADDITIONAL issues or adding context to existing ones.`
      : '';

    const systemPrompt = `You are an expert application security engineer (OWASP, SANS Top 25).
Your job is to review code for security vulnerabilities and respond ONLY with a JSON object.
Focus on real, exploitable vulnerabilities — not stylistic issues.
Map every issue to an OWASP Top 10 category (A01–A10).
Respond with ONLY valid JSON matching this schema:
{
  "issues": [
    {
      "line": <number>,
      "title": "<short vulnerability name>",
      "description": "<clear explanation of the risk and how it can be exploited>",
      "severity": "<critical|warning|info>",
      "owaspCategory": "<A01|A02|...|A10>",
      "fix": "<concrete code snippet or guidance to fix>"
    }
  ],
  "summary": "<one paragraph overall security assessment>",
  "overallRisk": "<critical|high|medium|low|none>"
}`;

    const userPrompt = `Review this ${language} code for security vulnerabilities:

\`\`\`${language}
${truncatedCode}
\`\`\`
${existingContext}

Return ONLY the JSON object.`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: this.getModel(),
        max_tokens: 2048,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }]
      })
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Anthropic API error ${response.status}: ${err}`);
    }

    const data = await response.json() as any;
    const text = data.content?.[0]?.text ?? '';

    let parsed: LLMAnalysisResponse;
    try {
      const clean = text.replace(/```json\n?|```/g, '').trim();
      parsed = JSON.parse(clean);
    } catch {
      console.error('Sentinel LLM: Failed to parse response:', text);
      return [];
    }

    return (parsed.issues ?? []).map((issue: LLMIssue, i: number): SecurityIssue => ({
      id: `llm-${i}-L${issue.line}-${Date.now()}`,
      ruleId: `llm-${issue.owaspCategory}`,
      title: issue.title,
      description: issue.description,
      severity: issue.severity,
      owaspCategory: issue.owaspCategory,
      line: issue.line,
      column: 0,
      matchedText: '',
      source: 'llm',
      fix: issue.fix
    }));
  }

  async generateFix(
    code: string,
    issue: SecurityIssue,
    language: string
  ): Promise<FixSuggestion | null> {
    const apiKey = await this.getApiKey();
    const lines = code.split('\n');
    const context = lines.slice(
      Math.max(0, issue.line - 5),
      Math.min(lines.length, issue.line + 5)
    ).join('\n');

    const systemPrompt = `You are a senior security engineer providing code fixes.
Return ONLY a JSON object with the fixed code snippet.
Schema:
{
  "description": "<what was fixed and why>",
  "replacement": "<the fixed code snippet — only the lines that need to change>",
  "explanation": "<brief explanation of the security improvement>"
}`;

    const userPrompt = `Fix this security issue in ${language}:

Issue: ${issue.title}
Severity: ${issue.severity}
OWASP: ${issue.owaspCategory}
Description: ${issue.description}

Code context (around line ${issue.line}):
\`\`\`${language}
${context}
\`\`\`

Return ONLY the JSON fix object.`;

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: this.getModel(),
          max_tokens: 1024,
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }]
        })
      });

      const data = await response.json() as any;
      const text = data.content?.[0]?.text ?? '';
      const clean = text.replace(/```json\n?|```/g, '').trim();
      const parsed = JSON.parse(clean);

      const targetLine = issue.line - 1;
      const range = new vscode.Range(
        new vscode.Position(targetLine, 0),
        new vscode.Position(targetLine, lines[targetLine]?.length ?? 0)
      );

      return {
        id: `fix-${issue.id}`,
        issueId: issue.id,
        description: parsed.description,
        replacement: parsed.replacement,
        explanation: parsed.explanation,
        range
      };
    } catch (e) {
      console.error('Sentinel: Fix generation failed:', e);
      return null;
    }
  }
}
