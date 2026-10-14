// verifies every named import in the browser modules resolves, without a browser
import { readdirSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join, resolve } from 'node:path';

const root = resolve(process.argv[2] || 'static/js');
const files = [];
for (const d of ['', 'views']) for (const f of readdirSync(join(root, d))) if (f.endsWith('.js')) files.push(join(root, d, f));
const exportsOf = {};
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  const names = new Set();
  for (const m of src.matchAll(/export\s+(?:async\s+)?(?:function|const|let|class)\s+([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of src.matchAll(/export\s*\{([^}]*)\}/g)) m[1].split(',').forEach((n) => names.add(n.trim().split(/\s+as\s+/).pop()));
  if (/export\s+default/.test(src)) names.add('default');
  exportsOf[f] = names;
}
let bad = 0;
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from\s*'(\.[^']+)'/g)) {
    const target = resolve(join(f, '..'), m[2]);
    const names = exportsOf[target];
    if (!names) { console.log(`${f}: cannot resolve ${m[2]}`); bad++; continue; }
    for (const n of m[1].split(',').map((x) => x.trim().split(/\s+as\s+/)[0]).filter(Boolean)) {
      if (!names.has(n)) { console.log(`${f}: '${n}' is not exported by ${m[2]}`); bad++; }
    }
  }
}
console.log(bad ? `${bad} problem(s)` : `ok: ${files.length} modules`);
process.exit(bad ? 1 : 0);
