const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');

const skipped = new Set(['node_modules', '.git', '.cache', 'dist', 'build', 'coverage']);
const inside = (root, target) => {
  const relative = path.relative(root, target);
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
};

function context({ prettier = false, write = false } = {}) {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--help') {
    console.log(`Usage: node ${path.basename(process.argv[1])} --project PATH --scope RELATIVE_PATH${write ? ' [--write]' : ''}\nDependencies come from the selected project. Formatting previews by default.`);
    return null;
  }
  let project, scope, apply = false;
  const seen = new Set();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (seen.has(arg)) throw new Error(`Duplicate option: ${arg}`);
    seen.add(arg);
    if (arg === '--write' && write) apply = true;
    else if (['--project', '--scope'].includes(arg) && args[i + 1] && !args[i + 1].startsWith('--')) {
      const value = args[++i];
      if (arg === '--project') project = value;
      else scope = value;
    } else throw new Error(`Unknown or incomplete option: ${arg}`);
  }
  if (!project || !scope) throw new Error('Select --project and --scope explicitly');
  const projectRoot = fs.realpathSync(project);
  if (!fs.statSync(projectRoot).isDirectory() || !fs.statSync(path.join(projectRoot, 'package.json')).isFile()) throw new Error('Select a project with package.json');
  if (path.isAbsolute(scope)) throw new Error('Scope must be relative to the selected project');
  const root = path.resolve(projectRoot, scope);
  if (!inside(projectRoot, root)) throw new Error('Scope escapes the selected project');
  const relativeParts = path.relative(projectRoot, root).split(path.sep).filter(Boolean);
  let component = projectRoot;
  for (const part of relativeParts) {
    component = path.join(component, part);
    if (fs.lstatSync(component).isSymbolicLink()) throw new Error('Scope cannot traverse links');
  }
  const files = [];
  const walk = target => {
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink()) throw new Error('Scope contains a link');
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
        if (!skipped.has(entry.name)) walk(path.join(target, entry.name));
      }
    } else if (stat.isFile() && target.endsWith('.ts')) files.push(target);
  };
  walk(root);
  const requireProject = createRequire(path.join(projectRoot, 'package.json'));
  return { root: fs.statSync(root).isDirectory() ? root : path.dirname(root), files: files.sort(), apply, ts: requireProject('typescript'), prettier: prettier ? requireProject('prettier') : undefined };
}

module.exports = { context, inside };
