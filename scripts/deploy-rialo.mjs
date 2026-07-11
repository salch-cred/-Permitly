import fs from 'node:fs/promises';
import crypto from 'node:crypto';

const rpc=process.env.RIALO_RPC_URL;
if(!rpc) throw new Error('Set RIALO_RPC_URL');
const keyPath=process.env.RIALO_DEPLOYER_KEY_PATH;
if(!keyPath) throw new Error('Set RIALO_DEPLOYER_KEY_PATH (never commit the key)');
const source=await fs.readFile(new URL('../contracts/agent_permit.rialo',import.meta.url),'utf8');
const key=JSON.parse(await fs.readFile(keyPath,'utf8'));
const payload={chainId:process.env.RIALO_CHAIN_ID||'rialo-devnet',source,sourceHash:crypto.createHash('sha256').update(source).digest('hex'),deployer:key.publicKey};
const signature=crypto.sign(null,Buffer.from(JSON.stringify(payload)),{key:key.privateKey,dsaEncoding:'ieee-p1363'}).toString('hex');
const method=process.env.RIALO_RPC_METHOD_DEPLOY||'deployProgram';
const response=await fetch(rpc,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params:[{...payload,signature}]})});
const result=await response.json();
if(!response.ok||result.error) throw new Error(JSON.stringify(result.error||result));
console.log(JSON.stringify(result.result,null,2));
