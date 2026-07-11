import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { evaluatePermit, id, nowIso } from '../../packages/core/policy.mjs';
import { createReceipt, verifyReceipt } from '../../packages/core/receipts.mjs';
import { scanForPromptInjection, firewallRules } from '../../packages/core/firewall.mjs';
import { encryptCredential, decryptCredential, redactCredential } from '../../packages/core/vault.mjs';
import { RialoAdapter } from '../../packages/rialo/adapter.mjs';
import { createPlatformRouter } from './platform-router.mjs';
import { SlidingWindowRateLimiter } from '../../packages/platform/rate-limit.mjs';
import { StripeBillingAdapter } from '../../packages/platform/billing.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(__dirname,'../web');
const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || '127.0.0.1';
const secret = process.env.RECEIPT_SIGNING_SECRET || 'development-only-secret-change-me';
const vaultSecret = process.env.VAULT_MASTER_SECRET || secret;
const adminToken = process.env.AGENTPERMIT_ADMIN_TOKEN || 'change-me-in-production';
const relayToken = process.env.RIALO_RELAY_TOKEN || 'change-me-in-production';
const store = await new Store(process.env.DATA_DIR || './data').init();
const rialo = new RialoAdapter({ dataDir: process.env.DATA_DIR || './data' });
const platform = createPlatformRouter();

const apiLimiter  = new SlidingWindowRateLimiter({ windowMs: 60_000, max: 120 });
const authLimiter = new SlidingWindowRateLimiter({ windowMs: 60_000, max: 10 });
const rawBody = req => new Promise((resolve,reject)=>{ const chunks=[]; req.on('data',c=>{chunks.push(c);if(chunks.reduce((s,b)=>s+b.length,0)>1e6)reject(new Error('body too large'));});req.on('end',()=>resolve(Buffer.concat(chunks))); });
const json = (res,status,payload) => { res.writeHead(status,{'content-type':'application/json','access-control-allow-origin':'*','access-control-allow-headers':'authorization,content-type','access-control-allow-methods':'GET,POST,PATCH,DELETE,OPTIONS'}); res.end(JSON.stringify(payload)); };
const auth = req => req.headers.authorization === `Bearer ${adminToken}` || Boolean(req.authContext);
const body = req => new Promise((resolve,reject)=>{ let s=''; req.on('data',c=>{s+=c;if(s.length>1e6)reject(new Error('body too large'));});req.on('end',()=>{try{resolve(s?JSON.parse(s):{});}catch(e){reject(e);}}); });
const requireAuth = (req,res) => auth(req) ? true : (json(res,401,{error:'unauthorized'}),false);

function isPrivateHost(hostname){
  if(['localhost','0.0.0.0','127.0.0.1','::1'].includes(hostname)) return true;
  if(net.isIP(hostname)===4){ const p=hostname.split('.').map(Number); return p[0]===10||p[0]===127||(p[0]===192&&p[1]===168)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===169&&p[1]===254); }
  return false;
}

async function executeProtected(request,wsId){
  if (!request.execute) return null;
  const target = new URL(request.url);
  if (target.protocol !== 'https:' || isPrivateHost(target.hostname)) throw new Error('Protected execution requires a public HTTPS target');
  const headers={'content-type':'application/json',...(request.headers||{})};
  if(request.credentialId){
    const item=store.get('credentials',request.credentialId);
    if(item?.workspaceId!==wsId) throw new Error('Credential is unavailable');
    if(!item||item.status!=='active') throw new Error('Credential is unavailable');
    const credential=decryptCredential(item.encrypted,vaultSecret);
    if(credential) headers['authorization']=credential.type==='bearer'?`Bearer ${credential.token}`:`Basic ${Buffer.from(`${credential.username}:${credential.password}`).toString('base64')}`;
  }
  const response=await fetch(target,{method:request.method||'POST',headers,body:JSON.stringify(request.body||{})});
  return {status:response.status,body:await response.text()};
}

async function route(req,res){
  if(req.method==='OPTIONS') return json(res,200,{});
  const p=req.url.split('?')[0];
  const ctx=await platform.context(req);
  if(ctx) req.authContext=ctx;

  // ---- Rialo Cruise: Gas-less Meta-Transaction Relay ----
  if(p==='/api/cruise/relay'&&req.method==='POST'){
    const b=await body(req);
    if(b.relayToken!==relayToken) return json(res,403,{error:'invalid_relay_token'});
    const {payload,signature}=b;
    if(!payload||!signature) return json(res,400,{error:'payload_and_signature_required'});
    try {
      // Verify the payload hasn't expired
      if(payload.expiresAt && Math.floor(Date.now()/1000)>payload.expiresAt) return json(res,400,{error:'meta_tx_expired'});
      // Record on Rialo (mock or RPC)
      const result=await rialo.record(payload.kind,{...payload.params,signer:payload.signer,nonce:payload.nonce,gasAmount:payload.gasAmount});
      // Log the relay event
      store.append('audit',{action:'cruise.relay',kind:payload.kind,signer:payload.signer,nonce:payload.nonce,txHash:result.txHash,gasAmount:payload.gasAmount,timestamp:Date.now()});
      return json(res,200,{success:true,txHash:result.txHash,block:result.block,status:result.status});
    } catch(error){
      return json(res,400,{error:`relay_failed: ${error.message}`});
    }
  }

  // ---- Rialo Cruise: Get Nonce ----
  if(p.startsWith('/api/cruise/nonce/')&&req.method==='GET'){
    const signer=p.slice('/api/cruise/nonce/'.length);
    try {
      const nonce=await rialo.getNonce(signer);
      return json(res,200,{signer,nonce});
    } catch(error){
      return json(res,400,{error:`nonce_failed: ${error.message}`});
    }
  }

  // ---- Rialo Cruise: Sponsored Permit (direct, no meta-tx) ----
  if(p==='/api/cruise/sponsored-permit'&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const b=await body(req);
    try {
      const result=await rialo.record('sponsored_issue_permit',{
        permitId:b.permitId||id(),
        agentId:b.agentId,
        policyId:b.policyId,
        scopeRoot:b.scopeRoot,
        budgetCap:b.budgetCap,
        maxPerAction:b.maxPerAction,
        expiresAt:b.expiresAt,
        signer:b.signer,
        nonce:b.nonce||0,
        gasAmount:b.gasAmount||1000
      });
      return json(res,200,{success:true,txHash:result.txHash,permitId:b.permitId});
    } catch(error){
      return json(res,400,{error:`sponsored_permit_failed: ${error.message}`});
    }
  }

  // ---- Rialo Cruise: Status ----
  if(p==='/api/cruise/status'&&req.method==='GET'){
    const health=await rialo.health();
    return json(res,200,{
      cruiseEnabled:health.cruiseEnabled,
      mode:health.mode,
      chainId:health.chainId,
      connected:health.connected,
      relayerConfigured:!!process.env.RIALO_RELAYER_KEY
    });
  }

  // ---- Health ----
  if(p==='/api/health'&&req.method==='GET'){
    const rialoHealth=await rialo.health();
    return json(res,200,{ok:true,rialo:rialoHealth});
  }

  // ---- Policies ----
  if(p==='/api/policies'&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const b=await body(req);
    const policyId=b.policyId||id();
    const policy={id:policyId,name:b.name,scopes:b.scopes,roleId:b.roleId,budgetCap:b.budgetCap||0,maxPerAction:b.maxPerAction||0,minApprovals:b.minApprovals||0,requiresTimelock:b.requiresTimelock||false,rateLimitPerMinute:b.rateLimitPerMinute||0,conditions:b.conditions||[],workspaceId:ctx.workspaceId,createdAt:nowIso()};
    store.put('policies',policy);
    await rialo.record('publishPolicy',{policyId,policyHash:sha256(JSON.stringify(policy)),version:1,roleId:b.roleId,minApprovals:b.minApprovals||0,requiresTimelock:b.requiresTimelock||false});
    return json(res,201,{policy});
  }

  if(p==='/api/policies'&&req.method==='GET'){
    const all=store.list('policies').filter(x=>x.workspaceId===ctx.workspaceId);
    return json(res,200,{policies:all});
  }

  // ---- Roles ----
  if(p==='/api/roles'&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const b=await body(req);
    const roleId=b.roleId||id();
    const role={id:roleId,name:b.name,scopes:b.scopes,maxBudget:b.maxBudget||0,maxPerAction:b.maxPerAction||0,canDelegate:b.canDelegate||false,canApprove:b.canApprove||false,workspaceId:ctx.workspaceId,createdAt:nowIso()};
    store.put('roles',role);
    return json(res,201,{role});
  }

  // ---- Agents ----
  if(p==='/api/agents'&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const b=await body(req);
    const agent={id:b.agentId||id(),controller:b.controller,roleId:b.roleId,active:true,workspaceId:ctx.workspaceId,createdAt:nowIso()};
    store.put('agents',agent);
    await rialo.record('registerAgent',{agentId:agent.id,controller:b.controller,roleId:b.roleId});
    return json(res,201,{agent});
  }

  // ---- Permits ----
  if(p==='/api/permits'&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const b=await body(req);
    const expiresAt=Math.floor(Date.now()/1000)+(b.expiresIn||3600);
    const permitId=b.permitId||id();
    const permit={id:permitId,agentId:b.agentId,policyId:b.policyId,scope:b.scope,budgetCap:b.budgetCap||0,maxPerAction:b.maxPerAction||0,expiresAt,status:'active',workspaceId:ctx.workspaceId,createdAt:nowIso()};
    store.put('permits',permit);
    await rialo.record('issuePermit',{permitId,agentId:b.agentId,policyId:b.policyId,scopeRoot:sha256(b.scope||''),budgetCap:b.budgetCap||0,maxPerAction:b.maxPerAction||0,expiresAt});
    return json(res,201,{permit});
  }

  if(p.startsWith('/api/permits/')&&p.endsWith('/freeze')&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const permitId=p.split('/')[3];
    const item=store.get('permits',permitId);
    if(!item||item.workspaceId!==ctx.workspaceId) return json(res,404,{error:'not_found'});
    item.status='frozen';
    store.put('permits',item);
    await rialo.record('freezePermit',{permitId});
    return json(res,200,{permit:item});
  }

  if(p.startsWith('/api/permits/')&&p.endsWith('/unfreeze')&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const permitId=p.split('/')[3];
    const item=store.get('permits',permitId);
    if(!item||item.workspaceId!==ctx.workspaceId) return json(res,404,{error:'not_found'});
    item.status='active';
    store.put('permits',item);
    await rialo.record('unfreezePermit',{permitId});
    return json(res,200,{permit:item});
  }

  // ---- Delegations ----
  if(p==='/api/delegations'&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const b=await body(req);
    const expiresAt=Math.floor(Date.now()/1000)+(b.expiresIn||3600);
    const delegation={id:b.delegationId||id(),agentId:b.agentId,delegate:b.delegate,scope:b.scope,expiresAt,active:true,workspaceId:ctx.workspaceId,createdAt:nowIso()};
    store.put('delegations',delegation);
    await rialo.record('createDelegation',{delegationId:delegation.id,agentId:b.agentId,delegate:b.delegate,scopeRoot:sha256(b.scope||''),expiresAt});
    return json(res,201,{delegation});
  }

  // ---- Stakes ----
  if(p==='/api/stakes/deposit'&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const b=await body(req);
    const stake={id:b.agentId||id(),agentId:b.agentId,amount:b.amount,status:'active',workspaceId:ctx.workspaceId,createdAt:nowIso()};
    store.put('stakes',stake);
    await rialo.record('depositStake',{agentId:b.agentId,amount:b.amount});
    return json(res,201,{stake});
  }

  // ---- Credentials ----
  if(p==='/api/credentials'&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const b=await body(req);
    const id_=b.credentialId||id();
    const encrypted=encryptCredential(b.value,vaultSecret);
    const credential={id:id_,name:b.name,provider:b.provider,configured:true,encrypted,workspaceId:ctx.workspaceId,createdAt:nowIso()};
    store.put('credentials',credential);
    await rialo.record('registerCredentialHash',{credentialId:id_,metadataHash:sha256(JSON.stringify({name:b.name,provider:b.provider}))});
    return json(res,201,{credential:{id:id_,name:b.name,provider:b.provider,configured:true}});
  }

  // ---- Approvals ----
  if(p.startsWith('/api/approvals/')&&p.endsWith('/vote')&&req.method==='POST'){
    if(!requireAuth(req,res)) return;
    const approvalId=p.split('/')[3];
    const b=await body(req);
    const item=store.get('approvals',approvalId);
    if(!item) return json(res,404,{error:'not_found'});
    item.votes=item.votes||[];
    item.votes.push({guardian:b.guardian,approved:b.approved,at:nowIso()});
    const yesVotes=item.votes.filter(v=>v.approved).length;
    if(yesVotes>=(item.requiredVotes||1)) item.status='approved';
    else if(item.votes.filter(v=>!v.approved).length>=(item.requiredVotes||1)) item.status='denied';
    store.put('approvals',item);
    await rialo.record('castVote',{approvalId,guardian:b.guardian,approved:b.approved});
    return json(res,200,{approval:item});
  }

  // ---- Action Authorization ----
  if(p==='/api/actions/authorize'&&req.method==='POST'){
    const b=await body(req);
    const permitItem=store.get('permits',b.permitId);
    if(!permitItem) return json(res,404,{error:'permit_not_found'});
    const wsId=permitItem.workspaceId;
    const agentItem=store.get('agents',permitItem.agentId||b.agentId);
    const policyItem=store.get('policies',permitItem.policyId);
    const scan=scanForPromptInjection(b.input||'',firewallRules);
    if(scan.score>=70){
      const receipt=createReceipt({permitId:b.permitId,actionHash:sha256(b.input||''),amount:0,result:'blocked_firewall',secret});
      store.put('receipts',receipt);
      await rialo.record('recordDenial',{permitId:b.permitId,actionHash:sha256(b.input||''),receiptId:receipt.id,previousHash:'',result:4});
      return json(res,200,{evaluation:{decision:'blocked',reason:'Prompt injection detected'},scan,receipt});
    }
    const evaluation=evaluatePermit({permit:permitItem,agent:agentItem,policy:policyItem,request:b});
    if(evaluation.decision==='authorized'){
      const amount=b.amount||0;
      permitItem.spent=(permitItem.spent||0)+amount;
      store.put('permits',permitItem);
      const receipt=createReceipt({permitId:b.permitId,actionHash:sha256(JSON.stringify(b)),amount,result:'authorized',secret});
      store.put('receipts',receipt);
      const execResult=b.execute?await executeProtected(b,wsId):null;
      await rialo.record('authorizeAndConsume',{permitId:b.permitId,actionHash:sha256(JSON.stringify(b)),amount,receiptId:receipt.id,previousHash:''});
      return json(res,200,{evaluation,receipt,scan,execution:execResult});
    }
    if(evaluation.decision==='escalated'){
      const approvalId=b.approvalId||id();
      const approval={id:approvalId,permitId:b.permitId,actionHash:sha256(JSON.stringify(b)),amount:b.amount||0,status:'pending',requiredVotes:policyItem?.minApprovals||1,votes:[],workspaceId:wsId,createdAt:nowIso()};
      store.put('approvals',approval);
      await rialo.record('requestApproval',{approvalId,permitId:b.permitId,actionHash:sha256(JSON.stringify(b)),amount:b.amount||0,requiredVotes:policyItem?.minApprovals||1});
      return json(res,200,{evaluation,approval,scan});
    }
    const receipt=createReceipt({permitId:b.permitId,actionHash:sha256(JSON.stringify(b)),amount:0,result:evaluation.decision,secret});
    store.put('receipts',receipt);
    await rialo.record('recordDenial',{permitId:b.permitId,actionHash:sha256(JSON.stringify(b)),receiptId:receipt.id,previousHash:'',result:evaluation.decision==='denied_budget'?2:evaluation.decision==='denied_scope'?3:4});
    return json(res,200,{evaluation,receipt,scan});
  }

  // ---- Receipts ----
  if(p.startsWith('/api/receipts/')&&p.endsWith('/verify')&&req.method==='GET'){
    const id=p.split('/')[3];
    const r=store.get('receipts',id);
    if(!r)return json(res,404,{error:'not_found'});
    return json(res,200,{valid:verifyReceipt(r,secret),receipt:r});
  }

  // ---- SaaS Platform Routes ----
  if(p.startsWith('/api/v1/')) {
    const handled=await platform.handle({req,res,path:p,json,readBody:body});
    if(handled) return;
  }

  // ---- Static Files ----
  if(p.startsWith('/api/')) return json(res,404,{error:'not_found'});
  const file=p==='/'?'landing.html':p==='/app'?'index.html':p==='/signup'?'signup.html':p==='/account'?'account.html':p.slice(1);
  const safe=path.normalize(file).replace(/^\.\.(\/|\\|$)/,'');
  try{const data=await fs.readFile(path.join(webRoot,safe));const ext=path.extname(safe);const types={'.html':'text/html','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml'};res.writeHead(200,{'content-type':types[ext]||'application/octet-stream'});res.end(data);}catch{json(res,404,{error:'not_found'});}
}

const server=http.createServer((req,res)=>route(req,res).catch(e=>json(res,500,{error:'internal_error',message:e.message})));
server.listen(port,host,()=>console.log(`AgentPermit running on ${host}:${port}`));
