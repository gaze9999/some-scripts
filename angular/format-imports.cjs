const fs = require('fs');
const path = require('path');
const { context } = require('./import-runtime.cjs');
const selected = context({ prettier: true, write: true });
if (!selected) return;
const { root, files, ts, prettier, apply } = selected;
const importEnd = (file, source) => {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  let end = 0;
  for (const statement of sf.statements) {
    if (!ts.isImportDeclaration(statement)) break;
    end = statement.end;
  }
  return end;
};

(async () => {
  const changed = [];
  for (const file of files.sort()) {
    const source = fs.readFileSync(file, 'utf8');
    const originalEnd = importEnd(file, source);
    if (!originalEnd) continue;
    const formatted = await prettier.format(source, {
      ...(await prettier.resolveConfig(file)),
      filepath: file,
    });
    const formattedEnd = importEnd(file, formatted);
    const prefix = formatted.slice(0, formattedEnd).trimEnd();
    const body = source.slice(originalEnd).replace(/^\s+/, '');
    const next = `${prefix}\n\n${body}`;
    if (next !== source) {
      if (apply) {
        if (fs.lstatSync(file).isSymbolicLink() || fs.readFileSync(file, 'utf8') !== source) throw new Error('Source changed during formatting preview');
        fs.writeFileSync(file, next, 'utf8');
      }
      changed.push(path.relative(root, file).replaceAll('\\', '/'));
    }
  }
  process.stdout.write(JSON.stringify({ mode: apply ? 'write' : 'preview', changed: changed.length, files: changed }, null, 2));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
