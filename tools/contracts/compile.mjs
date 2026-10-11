import solc from 'solc';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';

const root = new URL('../../', import.meta.url);
const version = solc.version();
if (version !== '0.8.26+commit.8a97fa7a.Emscripten.clang') {
  throw new Error('Unexpected Solidity compiler version');
}
const names = ['DemoVault', 'PatchedVault'];
const sources = Object.fromEntries(await Promise.all(names.map(async name => [
  `${name}.sol`, { content: await readFile(new URL(`contracts/src/${name}.sol`, root), 'utf8') },
])));
const input = {
  language: 'Solidity', sources,
  settings: {
    evmVersion: 'cancun', optimizer: { enabled: true, runs: 200 },
    metadata: { bytecodeHash: 'none' },
    outputSelection: { '*': { '*': ['evm.deployedBytecode.object', 'storageLayout'] } },
  },
};
const output = JSON.parse(solc.compile(JSON.stringify(input)));
for (const error of output.errors ?? []) {
  if (error.severity === 'error') throw new Error(error.formattedMessage);
}
const directory = new URL('fixtures/compiler/', root);
await mkdir(directory, { recursive: true });
for (const name of names) {
  const artifact = output.contracts[`${name}.sol`][name];
  const ledger = artifact.storageLayout.storage;
  if (ledger.length !== 1 || ledger[0].label !== 'credit' || ledger[0].slot !== '0' || ledger[0].offset !== 0) {
    throw new Error('Vault ledger must occupy slot zero');
  }
  const runtime = Buffer.from(artifact.evm.deployedBytecode.object, 'hex');
  if (!runtime.length || runtime.length > 24576) throw new Error('Runtime exceeds fixture bounds');
  await writeFile(new URL(`${name}.runtime.hex`, directory), `${runtime.toString('hex')}\n`);
  await writeFile(new URL(`${name}.json`, directory), `${JSON.stringify({
    compiler: version, settings: input.settings, contract: name,
    runtime_bytes: runtime.length,
    code_digest: createHash('sha256').update(runtime).digest('hex'),
    storage_layout: artifact.storageLayout,
  }, null, 2)}\n`);
  console.log(`${name}: compiled ${runtime.length} runtime bytes; ledger verified at slot 0`);
}
