import * as assert from 'assert';
import { SASTEngine } from '../../src/analysis/sastEngine';
import { SecurityIssue } from '../../src/utils/types';

suite('SAST Engine Tests', () => {
  let engine: SASTEngine;

  setup(() => {
    engine = new SASTEngine();
  });

  // ── SQL Injection ──────────────────────────────────────────────────────

  test('detects SQL injection via template literal', () => {
    const code = 'const query = `SELECT * FROM users WHERE id = ${userId}`;';
    const issues = engine.analyze(code, 'javascript');
    assert.ok(issues.length > 0, 'Should detect SQL injection');
    const sqli = issues.find((i: SecurityIssue) => i.ruleId.startsWith('sqli'));
    assert.ok(sqli, 'Should have a sqli rule match');
    assert.strictEqual(sqli!.severity, 'critical');
    assert.strictEqual(sqli!.owaspCategory, 'A03');
  });

  test('detects SQL injection via Python f-string', () => {
    const code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")';
    const issues = engine.analyze(code, 'python');
    const sqli = issues.find((i: SecurityIssue) => i.ruleId === 'sqli-003');
    assert.ok(sqli, 'Should detect Python f-string SQL injection');
    assert.strictEqual(sqli!.severity, 'critical');
  });

  test('does not flag parameterized queries', () => {
    const code = "db.execute('SELECT * FROM users WHERE id = ?', [userId]);";
    const issues = engine.analyze(code, 'javascript');
    const sqli = issues.filter((i: SecurityIssue) => i.ruleId.startsWith('sqli'));
    assert.strictEqual(sqli.length, 0, 'Parameterized queries should be safe');
  });

  // ── XSS ────────────────────────────────────────────────────────────────

  test('detects document.write XSS', () => {
    const code = 'document.write(location.search);';
    const issues = engine.analyze(code, 'javascript');
    const xss = issues.find((i: SecurityIssue) => i.ruleId === 'xss-002');
    assert.ok(xss, 'Should detect document.write XSS');
    assert.strictEqual(xss!.severity, 'critical');
  });

  // ── Broken Authentication ──────────────────────────────────────────────

  test('detects jwt.decode without verify', () => {
    const code = 'const decoded = jwt.decode(token);';
    const issues = engine.analyze(code, 'javascript');
    const auth = issues.find((i: SecurityIssue) => i.ruleId === 'auth-001');
    assert.ok(auth, 'Should detect jwt.decode usage');
    assert.strictEqual(auth!.owaspCategory, 'A07');
  });

  test('detects weak JWT algorithm "none"', () => {
    const code = "jwt.verify(token, secret, { algorithms: ['none'] });";
    const issues = engine.analyze(code, 'javascript');
    const auth = issues.find((i: SecurityIssue) => i.ruleId === 'auth-002');
    assert.ok(auth, 'Should detect none algorithm');
  });

  test('detects hardcoded passwords', () => {
    const code = "const password = 'SuperSecret123!';";
    const issues = engine.analyze(code, 'javascript');
    const auth = issues.find((i: SecurityIssue) => i.ruleId === 'auth-003');
    assert.ok(auth, 'Should detect hardcoded password');
    assert.strictEqual(auth!.severity, 'critical');
  });

  test('does not flag env-based credentials', () => {
    const code = "const password = process.env.DB_PASSWORD;";
    const issues = engine.analyze(code, 'javascript');
    const auth = issues.filter((i: SecurityIssue) => i.ruleId === 'auth-003');
    assert.strictEqual(auth.length, 0, 'Environment variable usage should be safe');
  });

  test('detects MD5 password hashing', () => {
    const code = "const hash = md5(password);";
    const issues = engine.analyze(code, 'javascript');
    const weak = issues.find((i: SecurityIssue) => i.ruleId === 'auth-004');
    assert.ok(weak, 'Should flag MD5 for passwords');
    assert.strictEqual(weak!.severity, 'warning');
  });

  // ── Command Injection ──────────────────────────────────────────────────

  test('detects exec with user input', () => {
    const code = "exec(`convert ${req.body.filename} -resize 200x200`, cb);";
    const issues = engine.analyze(code, 'javascript');
    const cmdi = issues.find((i: SecurityIssue) => i.ruleId === 'cmdi-001');
    assert.ok(cmdi, 'Should detect command injection');
    assert.strictEqual(cmdi!.severity, 'critical');
  });

  // ── Insecure Deserialization ────────────────────────────────────────────

  test('detects Python pickle.loads', () => {
    const code = "data = pickle.loads(user_input)";
    const issues = engine.analyze(code, 'python');
    const deser = issues.find((i: SecurityIssue) => i.ruleId === 'deser-002');
    assert.ok(deser, 'Should detect insecure pickle deserialization');
  });

  // ── Security Misconfiguration ──────────────────────────────────────────

  test('detects debug mode enabled', () => {
    const code = "app.run(debug=True)";
    const issues = engine.analyze(code, 'python');
    const misc = issues.find((i: SecurityIssue) => i.ruleId === 'misconfig-001');
    assert.ok(misc, 'Should detect debug mode');
    assert.strictEqual(misc!.severity, 'warning');
  });

  test('detects CORS wildcard', () => {
    const code = "cors({ origin: '*' })";
    const issues = engine.analyze(code, 'javascript');
    const misc = issues.find((i: SecurityIssue) => i.ruleId === 'misconfig-002');
    assert.ok(misc, 'Should detect CORS wildcard');
  });

  test('detects disabled TLS verification', () => {
    const code = "const opts = { rejectUnauthorized: false };";
    const issues = engine.analyze(code, 'javascript');
    const misc = issues.find((i: SecurityIssue) => i.ruleId === 'misconfig-003');
    assert.ok(misc, 'Should detect disabled TLS');
    assert.strictEqual(misc!.severity, 'critical');
  });

  // ── Comment Skipping ───────────────────────────────────────────────────

  test('skips commented-out code in JS', () => {
    const code = "// const decoded = jwt.decode(token);";
    const issues = engine.analyze(code, 'javascript');
    assert.strictEqual(issues.length, 0, 'Should not flag comments');
  });

  test('skips commented-out code in Python', () => {
    const code = "# cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")";
    const issues = engine.analyze(code, 'python');
    assert.strictEqual(issues.length, 0, 'Should not flag Python comments');
  });

  // ── General ────────────────────────────────────────────────────────────

  test('returns issues with correct structure', () => {
    const code = "const decoded = jwt.decode(token);";
    const issues = engine.analyze(code, 'javascript');
    assert.ok(issues.length > 0);
    const issue = issues[0];
    assert.ok(issue.id, 'Issue must have an id');
    assert.ok(issue.ruleId, 'Issue must have a ruleId');
    assert.ok(issue.title, 'Issue must have a title');
    assert.ok(issue.description, 'Issue must have a description');
    assert.ok(issue.severity, 'Issue must have a severity');
    assert.ok(issue.owaspCategory, 'Issue must have an OWASP category');
    assert.strictEqual(issue.source, 'sast', 'Source must be sast');
    assert.ok(issue.line >= 1, 'Line must be 1-indexed');
  });

  test('does not flag unrelated languages', () => {
    const code = "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")";
    const issues = engine.analyze(code, 'javascript');
    const sqli = issues.filter((i: SecurityIssue) => i.ruleId === 'sqli-003');
    assert.strictEqual(sqli.length, 0, 'Python rule should not fire for JavaScript');
  });

  test('returns empty array for clean code', () => {
    const code = `
const express = require('express');
const app = express();
app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});
`;
    const issues = engine.analyze(code, 'javascript');
    assert.strictEqual(issues.length, 0, 'Clean code should have no issues');
  });
});
