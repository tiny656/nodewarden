import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export function blockingResults(report, reviews, today = new Date().toISOString().slice(0, 10)) {
  if (report?.version !== '2.1.0' || !Array.isArray(report.runs) || report.runs.length === 0) {
    throw new Error('Missing or invalid SARIF security report');
  }
  const findings = [];
  for (const run of report.runs) {
    const tool = run.tool?.driver?.name;
    if (!tool || !Array.isArray(run.results)) throw new Error('Incomplete SARIF security report');
    for (const invocation of run.invocations || []) {
      if (invocation.executionSuccessful === false ||
        (invocation.toolExecutionNotifications || []).some((notification) => notification.level === 'error')) {
        throw new Error(`${tool} did not complete successfully`);
      }
    }
    for (const result of run.results) {
      const rule = run.tool.driver.rules?.find((candidate) => candidate.id === result.ruleId);
      const tags = rule?.properties?.tags || [];
      const severity = Number(rule?.properties?.['security-severity'] ?? result.properties?.['security-severity'] ?? 0);
      const relevant = tool !== 'CodeQL' || severity > 0 || tags.includes('security');
      if (!relevant) continue;
      const file = result.locations?.[0]?.physicalLocation?.artifactLocation?.uri || '';
      const filePath = decodeURIComponent(file).replaceAll('\\', '/').replace(/^\.\//, '');
      const reviewed = reviews.find((entry) => entry.tool === tool && entry.rule === result.ruleId &&
        entry.path === filePath && entry.expires >= today && entry.reason?.length >= 30 &&
        (!entry.messageIncludes || String(result.message?.text || '').includes(entry.messageIncludes)));
      if (!reviewed) findings.push({ tool, rule: result.ruleId || 'unknown', path: filePath,
        line: result.locations?.[0]?.physicalLocation?.region?.startLine ?? null });
    }
  }
  return findings;
}

export async function reportFiles(input) {
  // Some scanners (notably zizmor-action) return a file without an extension.
  if ((await stat(input)).isFile()) return [input];
  const files = [];
  for (const entry of await readdir(input, { withFileTypes: true })) {
    const filename = path.join(input, entry.name);
    if (entry.isDirectory()) files.push(...await reportFiles(filename));
    else if (entry.name.endsWith('.sarif')) files.push(filename);
  }
  return files;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (!process.argv[2]) throw new Error('A SARIF file or directory is required');
    const reviews = JSON.parse(await readFile(new URL('../.github/security-reviewed-findings.json', import.meta.url), 'utf8'));
    const files = await reportFiles(process.argv[2]);
    if (files.length === 0) throw new Error('Security scanner did not produce a SARIF report');
    let findings = [];
    for (const file of files) findings.push(...blockingResults(JSON.parse(await readFile(file, 'utf8')), reviews));
    for (const finding of findings) console.error(`${finding.tool}: ${finding.rule} at ${finding.path}:${finding.line ?? '?'}`);
    if (findings.length) throw new Error(`${findings.length} unreviewed security findings block deployment`);
    console.log('Security result gate passed; no unreviewed security findings.');
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
