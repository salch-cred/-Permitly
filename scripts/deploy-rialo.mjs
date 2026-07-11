// AgentPermit v4 deployer — deploys the improved Rialo governance contract
// Usage: RIALO_RPC_URL=<url> RIALO_DEPLOYER_KEY_PATH=./secrets/deployer.json node scripts/deploy-rialo.mjs

import fs from 'node:fs/promises';
import crypto from 'node:crypto';

const rpc = process.env.RIALO_RPC_URL;
if (!rpc) throw new Error('Set RIALO_RPC_URL (e.g. https://devnet.rialo.io:4101)');

const keyPath = process.env.RIALO_DEPLOYER_KEY_PATH;
if (!keyPath) throw new Error('Set RIALO_DEPLOYER_KEY_PATH (never commit the key). Run `npm run keygen` first.');

const sourcePath = new URL('../contracts/agent_permit.rialo', import.meta.url);
const source = await fs.readFile(sourcePath, 'utf8');
const sourceHash = crypto.createHash('sha256').update(source).digest('hex');

const key = JSON.parse(await fs.readFile(keyPath, 'utf8'));
const chainId = process.env.RIALO_CHAIN_ID || 'rialo:devnet';

const payload = {
  chainId,
  source,
  sourceHash,
  deployer: key.publicKey,
  contractVersion: '4.0.0',
  features: [
    'multi-sig-guardians',
    'delegation',
    'role-based-policies',
    'staking-slashing',
    'timelock',
    'policy-migration',
    'permit-freeze-unfreeze'
  ]
};

const payloadJson = JSON.stringify(payload);
const signature = crypto.sign(
  null,
  Buffer.from(payloadJson),
  { key: key.privateKey, dsaEncoding: 'ieee-p1363' }
).toString('hex');

const method = process.env.RIALO_RPC_METHOD_DEPLOY || 'deployProgram';

console.log(`\n  Deploying AgentPermit v4 to ${chainId}...`);
console.log(`  Contract size: ${(source.length / 1024).toFixed(1)} KB`);
console.log(`  Source hash:   ${sourceHash.slice(0, 16)}...`);
console.log(`  Deployer:      ${key.publicKey.slice(0, 40)}...\n`);

const response = await fetch(rpc, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method,
    params: [{ ...payload, signature }]
  })
});

const result = await response.json();

if (!response.ok || result.error) {
  console.error('Deployment failed:');
  throw new Error(JSON.stringify(result.error || result, null, 2));
}

const programId = result.result?.programId || result.result?.id;
console.log(`\n  ✅ Deployed!`);
console.log(`  Program ID:    ${programId}`);
console.log(`  Block:         ${result.result?.slot || result.result?.block || 'N/A'}`);
console.log(`  Tx Hash:       ${result.result?.signature || 'N/A'}\n`);
console.log(`  Add to .env:   RIALO_PROGRAM_ID=${programId}\n`);

// Output full result for scripting
console.log(JSON.stringify(result.result, null, 2));
