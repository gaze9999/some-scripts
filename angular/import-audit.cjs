const fs = require('fs');
const path = require('path');
const { context } = require('./import-runtime.cjs');
const selected = context();
if (!selected) return;
const { root, files, ts } = selected;

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
process.stdout.write(JSON.stringify({ files: files.length, analysis: 'Lexical identifier heuristic; template and symbol consumers require compiler/reference checks', results }, null, 2));
