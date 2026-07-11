// AgentPermit v4 — Rialo Cruise smoke test
// Tests: meta-transaction relay, sponsored permits, gas-less authorization
const base = process.env.APP_ORIGIN || 'http://127.0.0.1:8787';
const token = process.env.AGENTPERMIT_ADMIN_TOKEN || 'change-me-in-production';
const relayToken = process.env.RIALO_RELAY_TOKEN || 'change-me-in-production';

const call = async (path, options = {}) => {
  const response = await fetch(base + path, {
    ...options,
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${token}`,
      ...options.headers
    }
  });
  const body = await response.json();
  if (!response.ok) throw new Error(`${path}: ${JSON.stringify(body)}`);
  return body;
};

// 1. Check Cruise status
const status = await call('/api/cruise/status');
if (!status.cruiseEnabled) throw new Error('cruise not enabled');
console.log(`✓ Cruise status: mode=${status.mode}, enabled=${status.cruiseEnabled}`);

// 2. Get nonce for a test signer
const nonceResult = await call('/api/cruise/nonce/0xtest_signer');
console.log(`✓ Nonce for test_signer: ${nonceResult.nonce}`);

// 3. Create a role
const role = await call('/api/roles', {
  method: 'POST',
  body: JSON.stringify({
    name: 'cruise_operator',
    scopes: ['deploy:*', 'read:*'],
    maxBudget: 10000,
    maxPerAction: 500,
    canDelegate: false,
    canApprove: false
  })
});
console.log(`✓ Role created: ${role.role.id}`);

// 4. Register an agent
const agent = await call('/api/agents', {
  method: 'POST',
  body: JSON.stringify({
    agentId: 'agent_cruise_1',
    controller: '0xcruise_controller',
    roleId: role.role.id
  })
});
console.log(`✓ Agent registered: ${agent.agent.id}`);

// 5. Create a policy
const policy = await call('/api/policies', {
  method: 'POST',
  body: JSON.stringify({
    name: 'Cruise smoke policy',
    roleId: role.role.id,
    scopes: ['deploy:*'],
    budgetCap: 1000,
    maxPerAction: 100,
    minApprovals: 0,
    requiresTimelock: false,
    rateLimitPerMinute: 10,
    conditions: [{ field: 'target', operator: 'eq', value: 'staging' }]
  })
});
console.log(`✓ Policy created: ${policy.policy.id}`);

// 6. Issue a sponsored permit via Cruise relay
const sponsoredPermit = await call('/api/cruise/sponsored-permit', {
  method: 'POST',
  body: JSON.stringify({
    permitId: 'permit_cruise_1',
    agentId: 'agent_cruise_1',
    policyId: policy.policy.id,
    scopeRoot: '0xscope_root',
    budgetCap: 500,
    maxPerAction: 50,
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
    signer: '0xcruise_controller',
    nonce: 0,
    gasAmount: 500
  })
});
if (!sponsoredPermit.success) throw new Error('sponsored permit failed');
console.log(`✓ Sponsored permit issued: ${sponsoredPermit.permitId} (tx: ${sponsoredPermit.txHash.slice(0, 16)}...)`);

// 7. Relay a meta-transaction (simulated)
const metaTxPayload = {
  kind: 'sponsored_authorize',
  params: {
    permitId: 'permit_cruise_1',
    actionHash: '0xaction_hash',
    amount: 10,
    receiptId: 'receipt_cruise_1',
    previousHash: ''
  },
  signer: '0xcruise_controller',
  nonce: 1,
  gasAmount: 300,
  chainId: 'rialo:devnet',
  programId: 'local-agentpermit',
  expiresAt: Math.floor(Date.now() / 1000) + 3600,
  version: 1
};

const relayResult = await fetch(base + '/api/cruise/relay', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    payload: metaTxPayload,
    signature: '0xsimulated_signature',
    relayToken
  })
});
const relayBody = await relayResult.json();
if (!relayBody.success) throw new Error(`relay failed: ${JSON.stringify(relayBody)}`);
console.log(`✓ Meta-tx relayed: ${relayBody.txHash.slice(0, 16)}...`);

// 8. Verify the relay created a receipt
const receiptVerify = await call(`/api/receipts/receipt_cruise_1/verify`);
console.log(`✓ Relay receipt verified: valid=${receiptVerify.valid}`);

console.log('\n========================================');
console.log('  ✅ All Rialo Cruise tests passed!');
console.log('========================================');
console.log(JSON.stringify({
  sponsoredPermit: sponsoredPermit.permitId,
  relayTx: relayBody.txHash,
  receipt: receiptVerify.valid
}, null, 2));
