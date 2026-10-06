const fs = require('fs');
const path = require('path');
const { context } = require('./import-runtime.cjs');
const selected = context({ prettier: true });
if (!selected) return;
const { root, files, ts, prettier } = selected;
const declarations = (file, source) => {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  return sf.statements.filter(ts.isImportDeclaration);
};

(async () => {
  const result = {
    files: files.length,
    importFormattingMismatches: [],
    duplicateModules: [],
    defaultImports: [],
    defaultExports: [],
  };
  for (const file of files.sort()) {
    const source = fs.readFileSync(file, 'utf8');
    const imports = declarations(file, source);
    const relative = path.relative(root, file).replaceAll('\\', '/');
    if (imports.length) {
      const formatted = await prettier.format(source, {
        ...(await prettier.resolveConfig(file)),
        filepath: file,
      });
      const formattedImports = declarations(file, formatted);
      const currentText = imports.map(item => item.getText()).join('\n');
      const formattedText = formattedImports.map(item => item.getText()).join('\n');
      if (currentText !== formattedText) result.importFormattingMismatches.push(relative);

      const modules = new Map();
      for (const item of imports) {
        const name = item.moduleSpecifier.text;
        modules.set(name, (modules.get(name) || 0) + 1);
        if (item.importClause?.name) result.defaultImports.push({ file: relative, module: name });
      }
      for (const [module, count] of modules) {
        if (count > 1) result.duplicateModules.push({ file: relative, module, count });
      }
    }
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    for (const item of sf.statements) {
      if (ts.isExportAssignment(item) && !item.isExportEquals) result.defaultExports.push(relative);
    }
  }
  process.stdout.write(JSON.stringify(result, null, 2));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
