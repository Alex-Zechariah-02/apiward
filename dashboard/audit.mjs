// Reads `npm audit --json` on standard input and fails on every advisory at
// or above the given level, except the advisories listed in `allowed`, each
// with its reason and the release that ends it. A missing or failed audit
// fails too. Usage: npm audit --json | node audit.mjs <low|moderate|high|critical>
import { readFileSync } from 'node:fs';

const allowed = {
  // picomatch <= 4.0.7, ReDoS through repeated extglobs, no fixed release yet
  // (fix pending: micromatch/picomatch#254). Reached only through Vite's
  // build-time globbing of this project's own patterns, never in the built
  // files. Remove once a fixed picomatch is released and installed.
  'GHSA-fc5q-39xc-vjpf': 'build tooling only; no fixed release (since 2026-11-18)',
};
const levels = ['info', 'low', 'moderate', 'high', 'critical'];
const level = levels.indexOf(process.argv[2]);
if (level < 0) {
  console.error('usage: npm audit --json | node audit.mjs <low|moderate|high|critical>');
  process.exit(2);
}

const report = JSON.parse(readFileSync(0, 'utf8'));
if (report.error || !report.vulnerabilities) {
  console.error('npm audit gave no report:', JSON.stringify(report.error ?? report).slice(0, 500));
  process.exit(1);
}
const advisories = new Map();
for (const finding of Object.values(report.vulnerabilities)) {
  for (const cause of finding.via) {
    if (typeof cause === 'object') {
      advisories.set(cause.url.split('/').pop(), cause);
    }
  }
}
let failed = 0;
for (const [id, advisory] of advisories) {
  if (levels.indexOf(advisory.severity) < level) {
    continue;
  }
  const reason = allowed[id];
  console.log(`${reason ? 'allowed' : 'FAIL'} ${id} ${advisory.severity} ${advisory.name}: ${advisory.title}${reason ? ` (${reason})` : ''}`);
  failed += reason ? 0 : 1;
}
console.log(`${failed} advisories at or above ${process.argv[2]} not allowed`);
process.exit(failed > 0 ? 1 : 0);
