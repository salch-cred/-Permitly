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

  async record(kind, payload) {
    const envelope = {
      chainId: this.chainId,
      programId: this.programId,
      kind,
      payload,
      nonce: Date.now(),
      version: 1
    };

    if (this.mode === 'rpc') {
      // Real Rialo devnet: use sendTransaction via official CDK
      try {
        const client = await this.#getClient();
        // callWithJson allows arbitrary program invocations on devnet
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
        // Fall back to mock if RPC call fails (program not yet deployed)
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
      } catch {
        // Fall back to local ledger
      }
    }
    const file = path.join(this.dataDir, 'ledger.json');
    try {
      const ledger = JSON.parse(await fs.readFile(file, 'utf8'));
      return ledger.filter(x => x.payload?.id === key || x.payload?.permitId === key);
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
          blockHeight
        };
      } catch (error) {
        return { mode: 'rpc', chainId: this.chainId, rpcUrl: this.rpcUrl, connected: false, error: error.message };
      }
    }
    return { mode: 'mock', chainId: this.chainId, programId: this.programId, connected: true };
  }

  // Get live devnet balance for a public key
  async getBalance(publicKey) {
    try {
      const client = await this.#getClient();
      return await client.getBalance(publicKey);
    } catch (error) {
      return null;
    }
  }
}
