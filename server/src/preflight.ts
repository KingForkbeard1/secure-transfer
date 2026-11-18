// Runs before the database package loads. Node 22.12 and 22.13 crash (segfault) with it, so fail with a clear message instead.
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 14)) {
  console.error(`Node ${process.versions.node} is too old. Use Node 22.14 or newer.`);
  process.exit(1);
}
