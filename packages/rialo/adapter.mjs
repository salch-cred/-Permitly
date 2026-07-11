import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import { sha256 } from '../core/receipts.mjs';

export class RialoAdapter {
  constructor(config = {}) {
    this.mode = config.mode || process.env.RIALO_MODE || 'mock';
    this.rpcUrl = config.rpcUrl || process.env.RIALO_RPC_URL;
    this.chainId = config.chainId || process.env.RIALO_CHAIN_ID || 'rialo-devnet';
    this.programId = config.programId || process.env.RIALO_PROGRAM_ID || 'local-agentpermit';
    this.dataDir = config.dataDir || process.env.DATA_DIR || './data';
    this.methods = {
      submit: process.env.RIALO_RPC_METHOD_SUBMIT || 'sendTransaction',
      read: process.env.RIALO_RPC_METHOD_READ || 'getProgramState',
      status: process.env.RIALO_RPC_METHOD_STATUS || 'getTransaction'
    };
  }

  async record(kind, payload) {
    const envelope = { chainId: this.chainId, programId: this.programId, kind, payload, nonce: Date.now(), version: 1 };
    if (this.mode === 'rpc') return this.#rpc(this.methods.submit, [envelope]);
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
    if (this.mode === 'rpc') return this.#rpc(this.methods.read, [{ programId: this.programId, key }]);
    const file = path.join(this.dataDir, 'ledger.json');
    try {
      const ledger = JSON.parse(await fs.readFile(file, 'utf8'));
      return ledger.filter(x => x.payload?.id === key || x.payload?.permitId === key);
    } catch { return []; }
  }

  async health() {
    if (this.mode === 'mock') return { mode: 'mock', chainId: this.chainId, programId: this.programId, connected: true };
    try { await this.#rpc(this.methods.status, ['0x0']); return { mode: 'rpc', chainId: this.chainId, connected: true }; }
    catch (error) { return { mode: 'rpc', chainId: this.chainId, connected: false, error: error.message }; }
  }

  async #rpc(method, params) {
    if (!this.rpcUrl) throw new Error('RIALO_RPC_URL is required in rpc mode');
    const response = await fetch(this.rpcUrl, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: crypto.randomUUID(), method, params })
    });
    if (!response.ok) throw new Error(`Rialo RPC HTTP ${response.status}`);
    const json = await response.json();
    if (json.error) throw new Error(json.error.message || 'Rialo RPC error');
    return json.result;
  }
}
