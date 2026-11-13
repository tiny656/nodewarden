import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { blockingResults, reportFiles } from './check-security-results.mjs';

function report(tool = 'CodeQL', rule = 'security-rule', file = 'src/example.ts', security = true) {
  return { version: '2.1.0', runs: [{ tool: { driver: { name: tool,
    rules: [{ id: rule, properties: security ? { 'security-severity': '7.5', tags: ['security'] } : {} }] } },
    results: [{ ruleId: rule, message: { text: 'Example finding' }, locations: [{ physicalLocation: {
      artifactLocation: { uri: file }, region: { startLine: 10 } } }] }] }] };
}

test('security findings block regardless of a successful scanner exit status', () => {
  assert.equal(blockingResults(report(), []).length, 1);
  assert.equal(blockingResults(report('Semgrep OSS', 'audit-rule', 'src/example.ts', false), []).length, 1);
  assert.equal(blockingResults(report('CodeQL', 'style-rule', 'src/example.ts', false), []).length, 0);
});

test('reviews must match tool, rule, exact path and unexpired justification', () => {
  const review = { tool: 'CodeQL', rule: 'security-rule', path: 'src/example.ts', expires: '2027-02-13',
    reason: 'Reviewed test-only example with sufficient justification.' };
  assert.equal(blockingResults(report(), [review], '2026-11-13').length, 0);
  for (const change of [{ tool: 'other' }, { rule: 'other' }, { path: 'src/other.ts' }, { expires: '2026-01-01' }, { reason: '' }]) {
    assert.equal(blockingResults(report(), [{ ...review, ...change }], '2026-11-13').length, 1);
  }
});

test('scanner errors and missing output cannot masquerade as an empty successful scan', () => {
  for (const value of [{}, { version: '2.1.0', runs: [] }, { version: '2.1.0', runs: [{ tool: { driver: { name: 'scanner' } } }] }]) {
    assert.throws(() => blockingResults(value, []));
  }
  const failed = report();
  failed.runs[0].invocations = [{ executionSuccessful: false }];
  assert.throws(() => blockingResults(failed, []), /did not complete successfully/);
});

test('accepts scanner output files without extensions and finds SARIF directories', async (ctx) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'nodewarden-security-results-'));
  ctx.after(() => rm(directory, { recursive: true, force: true }));
  const extensionless = path.join(directory, 'zizmor');
  const sarif = path.join(directory, 'results.sarif');
  await writeFile(extensionless, JSON.stringify(report('zizmor')));
  await writeFile(sarif, JSON.stringify(report()));
  assert.deepEqual(await reportFiles(extensionless), [extensionless]);
  assert.deepEqual(await reportFiles(directory), [sarif]);
  await assert.rejects(() => reportFiles(path.join(directory, 'missing')));
});
