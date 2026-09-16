const fs = require('fs');
const path = require('path');
const ts = require('C:/projects/dev/sfap/sfap-web-component/node_modules/typescript');

const root = 'C:/projects/dev/sfap/sfap-web-component/apps/txn/f08/sacrm/src/app/sacrm190';
const files = [];
const walk = dir => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.name.endsWith('.ts')) files.push(full);
  }
};
walk(root);

const results = [];
for (const file of files.sort()) {
  const source = fs.readFileSync(file, 'utf8');
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const imported = [];
  for (const statement of sf.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause) continue;
    const clause = statement.importClause;
    if (clause.name) imported.push({ name: clause.name.text, module: statement.moduleSpecifier.text });
    const bindings = clause.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) imported.push({ name: bindings.name.text, module: statement.moduleSpecifier.text });
    if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) imported.push({ name: element.name.text, module: statement.moduleSpecifier.text });
    }
  }
  const used = new Map();
  const visit = node => {
    if (ts.isImportDeclaration(node)) return;
    if (ts.isIdentifier(node)) used.set(node.text, (used.get(node.text) || 0) + 1);
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);
  const unused = imported.filter(item => !used.has(item.name));
  if (unused.length) results.push({ file: path.relative(root, file).replaceAll('\\', '/'), unused });
}
process.stdout.write(JSON.stringify({ files: files.length, results }, null, 2));
