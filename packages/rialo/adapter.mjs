import fs from 'node:fs/promises';
import path from 'node:path';
import { sha256 } from '../core/receipts.mjs';

// Lazily import the official Rialo TS CDK (only used in rpc mode)
let _rialoSdk = null;
async function getRialoSdk() {
  if (!_rialoSdk) _rialoSdk = await import('@rialo/ts-cdk');
  return _rialoSdk;
}

export class RialoAdapter {
  constructor(config = {}) {
    this.mode = config.mode || process.env.RIALO_MODE || 'mock';
    this.rpcUrl = config.rpcUrl || process.env.RIALO_RPC_URL || 'https://devnet.rialo.io:4101';
    this.chainId = config.chainId || process.env.RIALO_CHAIN_ID || 'rialo:devnet';
    this.programId = config.programId || process.env.RIALO_PROGRAM_ID || 'local-agentpermit';
    this.dataDir = config.dataDir || process.env.DATA_DIR || './data';
    this._client = null;
  }

  async #getClient() {
    if (!this._client) {
      const sdk = await getRialoSdk();
      this._client = sdk.createRialoClient({
        chain: { id: this.chainId, name: this.chainId, rpcUrl: this.rpcUrl }
      });
    }
    return this._client;
  }

  /**
   * Record a governance event on the Rialo ledger.
   * Supports all v4 contract methods: agent ops, policy ops, permits, approvals, staking, delegation, timelock.
   */
  async record(kind, payload) {
    const envelope = {
      chainId: this.chainId,
      programId: this.programId,
      kind,
      payload,
      nonce: Date.now(),
      version: 4  // v4 contract
    };

    if (this.mode === 'rpc') {
      try {
        const client = await this.#getClient();
        const result = await client.callWithJson({
          programId: this.programId,
          method: kind,
          args: envelope
        });
        return {
          txHash: result?.signature || sha256(envelope),
          block: result?.slot || 0,
          status: 'finalized',
          ...envelope
        };
      } catch (error) {
        console.warn(`[RialoAdapter] RPC call failed (${error.message}), using mock fallback`);
        return this.#mockRecord(envelope);
      }
    }

    return this.#mockRecord(envelope);
  }

  async #mockRecord(envelope) {
    await fs.mkdir(this.dataDir, { recursive: true });
    const file = path.join(this.dataDir, 'ledger.json');
    let ledger = [];
    try { ledger = JSON.parse(await fs.readFile(file, 'utf8')); } catch {}
    const tx = { txHash: sha256(envelope), block: ledger.length + 1, status: 'finalized', ...envelope };
    ledger.push(tx);
    await fs.writeFile(file, JSON.stringify(ledger, null, 2));
    return tx;
  }

  /**
   * Read governance records by key (agent ID, permit ID, approval ID, etc.)
   */
  async read(key) {
    if (this.mode === 'rpc') {
      try {
        const client = await this.#getClient();
        const result = await client.getWorkflowLineage({ programId: this.programId, key });
        return result || [];
      } catch {
        // Fall back to local ledger
      }
    }
    const file = path.join(this.dataDir, 'ledger.json');
    try {
      const ledger = JSON.parse(await fs.readFile(file, 'utf8'));
      return ledger.filter(x =>
        x.payload?.id === key ||
        x.payload?.permitId === key ||
        x.payload?.agentId === key ||
        x.payload?.approvalId === key ||
        x.payload?.delegationId === key
      );
    } catch { return []; }
  }

  /**
   * Read all records of a specific kind (e.g. all permits, all stakes)
   */
  async readByKind(kind) {
    const file = path.join(this.dataDir, 'ledger.json');
    try {
      const ledger = JSON.parse(await fs.readFile(file, 'utf8'));
      return ledger.filter(x => x.kind === kind);
    } catch { return []; }
  }

  /**
   * Health check — returns connection status and chain info
   */
  async health() {
    if (this.mode === 'rpc') {
      try {
        const client = await this.#getClient();
        const health = await client.getHealth();
        const blockHeight = await client.getBlockHeight();
        return {
          mode: 'rpc',
          chainId: this.chainId,
          rpcUrl: this.rpcUrl,
          connected: health === 'ok',
          blockHeight,
          contractVersion: 4
        };
      } catch (error) {
        return {
          mode: 'rpc',
          chainId: this.chainId,
          rpcUrl: this.rpcUrl,
          connected: false,
          error: error.message,
          contractVersion: 4
        };
      }
    }
    return {
      mode: 'mock',
      chainId: this.chainId,
      programId: this.programId,
      connected: true,
      contractVersion: 4
    };
  }

  /**
   * Get live devnet balance for a public key
   */
  async getBalance(publicKey) {
    try {
      const client = await this.#getClient();
      return await client.getBalance(publicKey);
    } catch (error) {
      return null;
    }
  }

  // ============================================================
  // Convenience methods for v4 contract operations
  // ============================================================

  /** Record a permit issuance */
  async recordPermitIssued(permitId, agentId, policyId, roleId, expiresAt) {
    return this.record('issuePermit', { permitId, agentId, policyId, roleId, expiresAt });
  }

  /** Record an action authorization */
  async recordActionAuthorized(receiptId, permitId, actionHash, amount) {
    return this.record('authorizeAndConsume', { receiptId, permitId, actionHash, amount });
  }

  /** Record an approval request (multi-sig) */
  async recordApprovalRequested(approvalId, permitId, actionHash, amount, requiredVotes) {
    return this.record('requestApproval', { approvalId, permitId, actionHash, amount, requiredVotes });
  }

  /** Record a guardian vote */
  async recordVoteCast(approvalId, guardian, approved) {
    return this.record('castVote', { approvalId, guardian, approved });
  }

  /** Record a stake deposit */
  async recordStakeDeposited(agentId, amount) {
    return this.record('depositStake', { agentId, amount });
  }

  /** Record a stake slash */
  async recordStakeSlashed(agentId, amount, reason, receiptId) {
    return this.record('slashStake', { agentId, amount, reason, receiptId });
  }

  /** Record a delegation */
  async recordDelegationCreated(delegationId, agentId, delegate, scopeRoot, expiresAt) {
    return this.record('createDelegation', { delegationId, agentId, delegate, scopeRoot, expiresAt });
  }

  /** Record a timelock action */
  async recordTimelockScheduled(actionId, targetFn, executesAt) {
    return this.record('scheduleTimelockAction', { actionId, targetFn, executesAt });
  }

  /** Record a policy migration */
  async recordPolicyMigration(migrationId, policyId, fromVersion, toVersion) {
    return this.record('startPolicyMigration', { migrationId, policyId, fromVersion, toVersion });
  }
}
