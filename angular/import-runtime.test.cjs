const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { context } = require('./import-runtime.cjs');

function fixture(callback) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'import-scope-'));
  const previous = process.argv;
  try {
    fs.writeFileSync(path.join(root, 'package.json'), '{}');
    fs.mkdirSync(path.join(root, 'node_modules/typescript'), { recursive: true });
    fs.writeFileSync(path.join(root, 'node_modules/typescript/index.js'), 'module.exports={fixture:true}');
    fs.mkdirSync(path.join(root, 'src'));
    fs.writeFileSync(path.join(root, 'src/example.ts'), 'export const example = 1;');
    callback(root);
  } finally {
    process.argv = previous;
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.match(path.basename(root), /^import-scope-/);
    fs.rmSync(root, { recursive: true, force: true });
  }
}

test('selected project resolves its own dependency and one-file scope', () => fixture(root => {
  process.argv = ['node', 'import-audit.cjs', '--project', root, '--scope', 'src/example.ts'];
  const value = context();
  assert.equal(value.ts.fixture, true);
  assert.equal(value.apply, false);
  assert.equal(path.relative(value.root, value.files[0]), 'example.ts');
}));

test('formatting defaults to preview and requires the explicit write flag', () => fixture(root => {
  process.argv = ['node', 'format-imports.cjs', '--project', root, '--scope', 'src'];
  assert.equal(context({ write: true }).apply, false);
  process.argv.push('--write');
  assert.equal(context({ write: true }).apply, true);
}));

test('escaping scope is rejected before dependency use', () => fixture(root => {
  process.argv = ['node', 'import-audit.cjs', '--project', root, '--scope', '../other'];
  assert.throws(() => context(), /escapes/);
}));

test('duplicate and unsupported write options fail', () => fixture(root => {
  process.argv = ['node', 'import-audit.cjs', '--project', root, '--scope', 'src', '--write'];
  assert.throws(() => context(), /Unknown/);
  process.argv = ['node', 'import-audit.cjs', '--project', root, '--scope', 'src', '--scope', '.'];
  assert.throws(() => context(), /Duplicate/);
}));
