import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
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
    this.relayerKey = config.relayerKey || process.env.RIALO_RELAYER_KEY || null;
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
   */
  async record(kind, payload) {
    const envelope = {
      chainId: this.chainId,
      programId: this.programId,
      kind,
      payload,
      nonce: Date.now(),
      version: 4
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

  async read(key) {
    if (this.mode === 'rpc') {
      try {
        const client = await this.#getClient();
        const result = await client.getWorkflowLineage({ programId: this.programId, key });
        return result || [];
      } catch {}
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

  async readByKind(kind) {
    const file = path.join(this.dataDir, 'ledger.json');
    try {
      const ledger = JSON.parse(await fs.readFile(file, 'utf8'));
      return ledger.filter(x => x.kind === kind);
    } catch { return []; }
  }

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
          contractVersion: 4,
          cruiseEnabled: !!this.relayerKey
        };
      } catch (error) {
        return {
          mode: 'rpc',
          chainId: this.chainId,
          rpcUrl: this.rpcUrl,
          connected: false,
          error: error.message,
          contractVersion: 4,
          cruiseEnabled: false
        };
      }
    }
    return {
      mode: 'mock',
      chainId: this.chainId,
      programId: this.programId,
      connected: true,
      contractVersion: 4,
      cruiseEnabled: true
    };
  }

  async getBalance(publicKey) {
    try {
      const client = await this.#getClient();
      return await client.getBalance(publicKey);
    } catch (error) {
      return null;
    }
  }

  // ============================================================
  // Rialo Cruise: Gas-less Meta-Transaction Support
  // ============================================================

  /**
   * Create a meta-transaction payload that an agent/user signs off-chain.
   * The relayer (Permitly backend) submits it, paying the gas.
   *
   * @param {string} kind - Contract method name (e.g. 'sponsored_issue_permit')
   * @param {object} params - Parameters for the contract method
   * @param {string} signerAddress - Address of the user signing (agent controller)
   * @param {number} nonce - Current nonce for this signer (prevents replay)
   * @param {number} gasAmount - Estimated gas cost in kelvins
   * @returns {object} metaTxPayload - The payload to be signed
   */
  createMetaTxPayload(kind, params, signerAddress, nonce, gasAmount = 1000) {
    const payload = {
      kind,
      params,
      signer: signerAddress,
      nonce,
      gasAmount,
      chainId: this.chainId,
      programId: this.programId,
      expiresAt: Math.floor(Date.now() / 1000) + 3600, // 1 hour expiry
      version: 1
    };
    return payload;
  }

  /**
   * Sign a meta-transaction payload with a user's keypair.
   * The signature proves the user authorized this specific action.
   *
   * @param {object} payload - Meta-tx payload from createMetaTxPayload
   * @param {object} signerKeypair - User's Keypair (from @rialo/ts-cdk)
   * @returns {string} hex-encoded signature
   */
  async signMetaTxPayload(payload, signerKeypair) {
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload, Object.keys(payload).sort()));
    const signature = await signerKeypair.sign(payloadBytes);
    return Buffer.from(signature).toString('hex');
  }

  /**
   * Verify a meta-transaction signature.
   *
   * @param {object} payload - The original meta-tx payload
   * @param {string} signatureHex - Hex-encoded signature
   * @param {object} signerPublicKey - Public key of the claimed signer
   * @returns {boolean} whether the signature is valid
   */
  async verifyMetaTxSignature(payload, signatureHex, signerPublicKey) {
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload, Object.keys(payload).sort()));
    const signature = Buffer.from(signatureHex, 'hex');
    return signerPublicKey.verify(payloadBytes, signature);
  }

  /**
   * Submit a meta-transaction through the relay endpoint.
   * The relayer (Permitly backend) pays the gas fee.
   *
   * @param {object} payload - Meta-tx payload
   * @param {string} signature - Hex-encoded user signature
   * @param {string} relayEndpoint - URL of the relay API (e.g. 'http://localhost:8787/api/cruise/relay')
   * @returns {object} relay result
   */
  async relayMetaTx(payload, signature, relayEndpoint) {
    const response = await fetch(relayEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        payload,
        signature,
        relayToken: process.env.RIALO_RELAY_TOKEN || ''
      })
    });
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Relay failed: ${err}`);
    }
    return response.json();
  }

  /**
   * Get the current nonce for a signer address.
   * Used when constructing meta-tx payloads.
   */
  async getNonce(signerAddress) {
    if (this.mode === 'rpc') {
      try {
        const client = await this.#getClient();
        const result = await client.callWithJson('getMetaTxNonce', {
          programId: this.programId,
          signer: signerAddress
        });
        return Number(result) || 0;
      } catch {}
    }
    // Mock mode: read from ledger
    const file = path.join(this.dataDir, 'ledger.json');
    try {
      const ledger = JSON.parse(await fs.readFile(file, 'utf8'));
      const metaTxs = ledger.filter(x =>
        x.kind === 'sponsored_issue_permit' ||
        x.kind === 'sponsored_authorize' ||
        x.kind === 'sponsored_record_denial'
      );
      return metaTxs.length;
    } catch { return 0; }
  }

  // ============================================================
  // Convenience methods for v4 contract operations
  // ============================================================

  async recordPermitIssued(permitId, agentId, policyId, roleId, expiresAt) {
    return this.record('issuePermit', { permitId, agentId, policyId, roleId, expiresAt });
  }

  async recordActionAuthorized(receiptId, permitId, actionHash, amount) {
    return this.record('authorizeAndConsume', { receiptId, permitId, actionHash, amount });
  }

  async recordApprovalRequested(approvalId, permitId, actionHash, amount, requiredVotes) {
    return this.record('requestApproval', { approvalId, permitId, actionHash, amount, requiredVotes });
  }

  async recordVoteCast(approvalId, guardian, approved) {
    return this.record('castVote', { approvalId, guardian, approved });
  }

  async recordStakeDeposited(agentId, amount) {
    return this.record('depositStake', { agentId, amount });
  }

  async recordStakeSlashed(agentId, amount, reason, receiptId) {
    return this.record('slashStake', { agentId, amount, reason, receiptId });
  }

  async recordDelegationCreated(delegationId, agentId, delegate, scopeRoot, expiresAt) {
    return this.record('createDelegation', { delegationId, agentId, delegate, scopeRoot, expiresAt });
  }

  async recordTimelockScheduled(actionId, targetFn, executesAt) {
    return this.record('scheduleTimelockAction', { actionId, targetFn, executesAt });
  }

  async recordPolicyMigration(migrationId, policyId, fromVersion, toVersion) {
    return this.record('startPolicyMigration', { migrationId, policyId, fromVersion, toVersion });
  }

  // ============================================================
  // Rialo Cruise convenience methods
  // ============================================================

  /** Record a sponsored (gas-less) permit issuance */
  async recordSponsoredPermitIssued(permitId, agentId, policyId, roleId, expiresAt, signer, nonce, gasAmount) {
    return this.record('sponsored_issue_permit', {
      permitId, agentId, policyId, roleId, expiresAt, signer, nonce, gasAmount
    });
  }

  /** Record a sponsored (gas-less) authorization */
  async recordSponsoredAuthorization(receiptId, permitId, actionHash, amount, signer, nonce, gasAmount) {
    return this.record('sponsored_authorize', {
      receiptId, permitId, actionHash, amount, signer, nonce, gasAmount
    });
  }

  /** Record a sponsored (gas-less) denial */
  async recordSponsoredDenial(permitId, actionHash, receiptId, previousHash, result, signer, nonce, gasAmount) {
    return this.record('sponsored_record_denial', {
      permitId, actionHash, receiptId, previousHash, result, signer, nonce, gasAmount
    });
  }
}
