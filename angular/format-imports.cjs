const fs = require('fs');
const path = require('path');
const ts = require('C:/projects/dev/sfap/sfap-web-component/node_modules/typescript');
const prettier = require('C:/projects/dev/sfap/sfap-web-component/node_modules/prettier');

const root = 'C:/projects/dev/sfap/sfap-web-component/apps/txn/f08/sacrm/src/app/sacrm190';
const files = [];
const walk = dir => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.name.endsWith('.ts')) files.push(full);
  }
};
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
  walk(root);
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
      fs.writeFileSync(file, next, 'utf8');
      changed.push(path.relative(root, file).replaceAll('\\', '/'));
    }
  }
  process.stdout.write(JSON.stringify({ changed: changed.length, files: changed }, null, 2));
})();
