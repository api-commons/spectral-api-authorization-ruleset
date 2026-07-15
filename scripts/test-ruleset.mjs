#!/usr/bin/env node
// Test harness for @api-common/spectral-api-authorization-ruleset.
//
// For each of the two lint targets (OpenAPI, OAuth AS metadata) it lints the
// noncompliant + clean fixture with the matching ruleset and asserts:
//   1. the noncompliant fixture fires every expected rule
//   2. the clean fixture is completely silent (no error AND no warn)
//   3. no rule throws while linting either document
//
// No test framework — spawn Spectral, parse JSON, assert, exit non-zero on
// failure so `npm test` / CI gate on it.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');
let failures = 0;

function lint(fixture, ruleset) {
  const file = resolve(root, 'fixtures', fixture);
  const rules = resolve(root, ruleset);
  const bin = resolve(root, 'node_modules', '.bin', 'spectral');
  const outFile = resolve(tmpdir(), `authz-spectral-${fixture.replace(/\W/g, '_')}-${process.pid}.json`);
  const res = spawnSync(
    bin,
    ['lint', file, '-r', rules, '-f', 'json', '-o', outFile],
    { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024 * 32 }
  );
  const stderr = res.stderr || '';
  if (/threw|exception|Error running|Cannot read|is not a function/i.test(stderr)) {
    console.error(`  RULE ERROR while linting ${fixture}:`);
    console.error(stderr.trim());
    failures++;
  }
  let json;
  try {
    json = JSON.parse(readFileSync(outFile, 'utf8').trim() || '[]');
  } catch (e) {
    console.error(`Failed to parse Spectral JSON output for ${fixture}.`);
    console.error('stdout:', res.stdout);
    console.error('stderr:', res.stderr);
    process.exit(2);
  } finally {
    try { rmSync(outFile, { force: true }); } catch {}
  }
  return json;
}

function checkTarget({ label, ruleset, badFixture, cleanFixture, expectedRules }) {
  console.log(`\n############ ${label} ############`);

  console.log(`== Linting NONCOMPLIANT fixture (${badFixture}) ==`);
  const bad = lint(badFixture, ruleset);
  const fired = new Set(bad.map((r) => r.code));
  console.log(`Noncompliant fixture: ${bad.length} findings across ${fired.size} rules.`);
  for (const rule of expectedRules) {
    if (!fired.has(rule)) {
      console.error(`  MISSING: expected rule "${rule}" did not fire on ${badFixture}.`);
      failures++;
    }
  }
  const unexpected = [...fired].filter((c) => !expectedRules.includes(c));
  if (unexpected.length) {
    console.error(`  UNEXPECTED rules fired on ${badFixture}: ${unexpected.join(', ')}`);
    failures++;
  }

  console.log(`== Linting CLEAN fixture (${cleanFixture}) ==`);
  const clean = lint(cleanFixture, ruleset);
  console.log(`Clean fixture: ${clean.length} findings.`);
  if (clean.length > 0) {
    console.error('  Clean fixture is not silent. Findings:');
    for (const f of clean) {
      console.error(`    ${f.code} @ ${(f.path || []).join('.')} — ${f.message}`);
    }
    failures++;
  } else {
    console.log('  OK: clean fixture is silent.');
  }
}

checkTarget({
  label: 'OpenAPI target',
  ruleset: 'api-authorization-openapi.yaml',
  badFixture: 'openapi-noncompliant.yaml',
  cleanFixture: 'openapi-clean.yaml',
  expectedRules: [
    'authz-transport-https-servers',
    'authz-global-security-defined',
    'authz-grant-no-implicit',
    'authz-grant-no-password',
    'authz-grant-types-allowed',
    'authz-oauth2-https-urls',
    'authz-oauth2-scopes-defined',
  ],
});

checkTarget({
  label: 'OAuth AS Metadata target',
  ruleset: 'api-authorization-oauth-metadata.yaml',
  badFixture: 'oauth-metadata-noncompliant.json',
  cleanFixture: 'oauth-metadata-clean.json',
  expectedRules: [
    'authz-meta-issuer-https',
    'authz-meta-endpoints-present',
    'authz-meta-no-implicit-response-type',
    'authz-meta-grant-no-password',
    'authz-meta-response-types-code-only',
    'authz-meta-iss-parameter',
    'authz-meta-pkce-s256',
    'authz-meta-client-auth-no-secret',
    'authz-meta-client-auth-strong',
    'authz-meta-sender-constraining',
    'authz-meta-par-required',
    'authz-meta-no-none-alg',
    'authz-meta-asym-signing',
  ],
});

console.log('');
if (failures > 0) {
  console.error(`FAILED with ${failures} problem(s).`);
  process.exit(1);
}
console.log('PASSED: both targets fire every expected rule on the noncompliant fixtures and are silent on the clean fixtures, with no rule throwing.');
