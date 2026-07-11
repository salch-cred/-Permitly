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
    if(credential.type==='bearer') headers.authorization=`Bearer ${credential.token}`;
    if(credential.type==='api-key') headers[credential.header||'x-api-key']=credential.value;
    if(credential.headers) Object.assign(headers,credential.headers);
  }
  const ctrl = new AbortController(); const timer=setTimeout(()=>ctrl.abort(),5000);
  try { const r=await fetch(target,{method:request.method||'POST',headers,body:request.payload?JSON.stringify(request.payload):undefined,signal:ctrl.signal}); return {status:r.status,body:(await r.text()).slice(0,5000)}; }
  finally{clearTimeout(timer);}
}

async function createDecisionReceipt(request,permit,evaluation,execution=null,wsId='ws_demo'){
  const previous=store.list('receipts').filter(x=>x.workspaceId===wsId).at(-1)?.hash||'GENESIS';
  const receipt=createReceipt({request,permit:permit||{id:request.permitId||'missing',workspaceId:wsId},evaluation,execution,previousHash:previous,secret});
  await store.add('receipts',receipt);
  const tx=await rialo.record('action_receipt',receipt);
  return {receipt,tx};
}

async function route(req,res){
  if(req.method==='OPTIONS') return json(res,204,{});
  // Rate limiting
  const ip = req.socket?.remoteAddress || 'unknown';
  const limiter = req.url?.startsWith('/api/v1/auth/') ? authLimiter : apiLimiter;
  const rate = limiter.consume(ip);
  if(!rate.allowed){
    res.writeHead(429,{'content-type':'application/json','retry-after':String(Math.ceil(rate.retryAfterMs/1000)),'access-control-allow-origin':'*'});
    return res.end(JSON.stringify({error:'rate_limited',retryAfterMs:rate.retryAfterMs}));
  }
  const url=new URL(req.url,'http://localhost');
  const p=url.pathname;
  if(await platform.handle({req,res,path:p,json,readBody:body})) return;
  req.authContext=await platform.context(req);
  const wsId=req.authContext?.workspaceId||'ws_demo';
  if(req.authContext&&!store.get('workspaces',wsId)) await store.add('workspaces',{id:wsId,name:'SaaS workspace',emergencyStopped:false});
  const workspace=()=>store.get('workspaces',wsId);
  const scoped=k=>store.list(k).filter(x=>x.workspaceId===wsId);
  const getScoped=(k,id)=>{const item=store.get(k,id);return item?.workspaceId===wsId?item:null};
  if(p==='/api/health') return json(res,200,{ok:true,service:'agentpermit',time:nowIso(),rialo:await rialo.health(),emergencyStopped:Boolean(workspace()?.emergencyStopped)});
  if(p==='/api/rialo/balance' && req.method==='GET'){
    const health = await rialo.health();
    let balance = null;
    const pubKey = process.env.RIALO_PUBLIC_KEY;
    if(pubKey) { try { const raw = await rialo.getBalance(pubKey); balance = raw !== null ? String(raw) : null; } catch {} }
    return json(res,200,{...health,balance,publicKey:pubKey||null});
  }
  if(p==='/api/summary'){
    const receipts=scoped('receipts');
    return json(res,200,{agents:scoped('agents').length,activeAgents:scoped('agents').filter(x=>x.workspaceId===wsId&&x.status==='active').length,policies:scoped('policies').length,permits:scoped('permits').length,receipts:receipts.length,blocked:receipts.filter(x=>x.result==='blocked').length,escalated:receipts.filter(x=>x.result==='escalated').length,pendingApprovals:scoped('approvals').filter(x=>x.status==='pending').length,securityEvents:scoped('securityEvents').length,emergencyStopped:Boolean(workspace()?.emergencyStopped)});
  }
  for(const k of ['agents','policies','permits','receipts','approvals','securityEvents','incidents']) if(p===`/api/${k}` && req.method==='GET') return json(res,200,{items:scoped(k)});
  if(p==='/api/receipts/export.csv' && req.method==='GET'){
    const receipts=scoped('receipts');
    const cols=['id','agentId','permitId','scope','target','amount','result','code','reason','hash','createdAt'];
    const csv=[cols.join(','),...receipts.map(r=>cols.map(c=>JSON.stringify(r[c]??'')).join(','))].join('\n');
    res.writeHead(200,{'content-type':'text/csv;charset=utf-8','content-disposition':'attachment; filename="permitly-receipts.csv"','access-control-allow-origin':'*'});
    return res.end(csv);
  }
  if(p==='/api/credentials' && req.method==='GET') return json(res,200,{items:scoped('credentials').map(redactCredential)});
  if(p==='/api/security/rules' && req.method==='GET') return json(res,200,{items:firewallRules()});

  if(p==='/api/agents' && req.method==='POST'){
    if(!requireAuth(req,res))return; const b=await body(req);
    const agent={id:id('agent'),workspaceId:wsId,name:b.name,type:b.type||'custom',status:'active',risk:0,createdAt:nowIso()};
    await store.add('agents',agent); await rialo.record('agent_registered',agent); return json(res,201,{agent});
  }

  if(p==='/api/policies' && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const b=await body(req);
    if(!b.name||!Array.isArray(b.scopes)||!b.scopes.length) return json(res,400,{error:'name_and_scopes_required'});
    const policy={id:id('pol'),workspaceId:wsId,name:b.name,scopes:b.scopes,budgetCap:Number(b.budgetCap||0),maxPerAction:Number(b.maxPerAction||0),rateLimitPerMinute:Number(b.rateLimitPerMinute||60),requireHumanAbove:Number(b.requireHumanAbove||0),conditions:Array.isArray(b.conditions)?b.conditions:[],status:'active',version:1,createdAt:nowIso()};
    await store.add('policies',policy); const tx=await rialo.record('policy_published',{...policy,conditionsHash:policy.conditions});
    return json(res,201,{policy,tx});
  }

  if(p==='/api/permits' && req.method==='POST'){
    if(!requireAuth(req,res))return;
    if(workspace()?.emergencyStopped) return json(res,423,{error:'workspace_emergency_stopped'});
    const b=await body(req); const issuedAt=nowIso();
    const permit={id:id('permit'),workspaceId:wsId,agentId:b.agentId,policyId:b.policyId||null,scopes:b.scopes||[],budgetCap:Number(b.budgetCap||0),maxPerAction:b.maxPerAction==null?null:Number(b.maxPerAction),rateLimitPerMinute:Number(b.rateLimitPerMinute||60),requireHumanAbove:b.requireHumanAbove==null?null:Number(b.requireHumanAbove),allowedTargets:b.allowedTargets||[],status:'active',issuedAt,expiresAt:b.expiresAt||new Date(Date.now()+86400000).toISOString()};
    if(!getScoped('agents',permit.agentId)) return json(res,400,{error:'unknown_agent'});
    await store.add('permits',permit); const tx=await rialo.record('permit_issued',permit);
    return json(res,201,{permit,tx});
  }

  const bulkRevoke=p.match(/^\/api\/agents\/([^/]+)\/revoke-permits$/);
  if(bulkRevoke && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const agent=getScoped('agents',bulkRevoke[1]); if(!agent)return json(res,404,{error:'not_found'});
    const revokedAt=nowIso();
    const revoked=await store.updateMany('permits',x=>x.workspaceId===wsId&&x.agentId===bulkRevoke[1]&&x.status==='active',{status:'revoked',revokedAt});
    const tx=await rialo.record('permits_bulk_revoked',{agentId:bulkRevoke[1],count:revoked.length,revokedAt});
    return json(res,200,{revoked:revoked.length,tx});
  }

  const clonePermit=p.match(/^\/api\/permits\/([^/]+)\/clone$/);
  if(clonePermit && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const source=getScoped('permits',clonePermit[1]); if(!source)return json(res,404,{error:'not_found'});
    const b=await body(req);
    const {revokedAt:_r,...rest}=source;
    const clone={...rest,id:id('permit'),issuedAt:nowIso(),expiresAt:b.expiresAt||new Date(Date.now()+86400000).toISOString(),status:'active'};
    await store.add('permits',clone);
    const tx=await rialo.record('permit_issued',clone);
    return json(res,201,{permit:clone,tx});
  }

  const revoke=p.match(/^\/api\/permits\/([^/]+)\/revoke$/);
  if(revoke && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const existing=getScoped('permits',revoke[1]); if(!existing)return json(res,404,{error:'not_found'});
    const permit=await store.update('permits',revoke[1],{status:'revoked',revokedAt:nowIso()});
    if(!permit)return json(res,404,{error:'not_found'}); const tx=await rialo.record('permit_revoked',permit); return json(res,200,{permit,tx});
  }

  if(p==='/api/actions/authorize' && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const request=await body(req); const permit=getScoped('permits',request.permitId);
    let evaluation;
    const scan=scanForPromptInjection({input:request.input,payload:request.payload,context:request.context});
    if(scan.score>0) await store.add('securityEvents',{id:id('sec'),workspaceId:wsId,agentId:request.agentId,permitId:request.permitId,scan,createdAt:nowIso()});
    if(workspace()?.emergencyStopped) evaluation={decision:'blocked',code:'emergency_stop',reason:'Workspace emergency stop is active'};
    else if(!scan.safe) evaluation={decision:scan.recommendation==='block'?'blocked':'escalated',code:'prompt_injection_risk',reason:`Prompt firewall detected ${scan.matches.map(x=>x.label).join(', ')}`};
    else evaluation=evaluatePermit({permit,request,receipts:scoped('receipts')});
    let execution=null;
    if(evaluation.decision==='authorized') { try{ execution=await executeProtected(request,wsId); } catch(error){ evaluation={decision:'blocked',code:'execution_failed',reason:error.message}; } }
    const {receipt,tx}=await createDecisionReceipt(request,permit,evaluation,execution,wsId);
    // Auto-update agent risk score based on decision history
    if(request.agentId){
      const agentReceipts=store.list('receipts').filter(r=>r.agentId===request.agentId&&r.workspaceId===wsId);
      if(agentReceipts.length>=3){
        const bad=agentReceipts.filter(r=>r.result!=='authorized').length;
        await store.update('agents',request.agentId,{risk:Math.min(100,Math.round((bad/agentReceipts.length)*100))});
      }
    }
    let approval=null;
    if(evaluation.decision==='escalated') approval=await store.add('approvals',{id:id('approval'),workspaceId:wsId,receiptId:receipt.id,permitId:request.permitId,agentId:request.agentId,action:{scope:request.scope,target:request.target||null,amount:Number(request.amount||0)},status:'pending',reason:evaluation.reason,createdAt:nowIso()});
    return json(res,200,{evaluation,scan,receipt,approval,tx});
  }

  const approvalAction=p.match(/^\/api\/approvals\/([^/]+)\/(approve|deny)$/);
  if(approvalAction && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const [_,approvalId,action]=approvalAction; const approval=getScoped('approvals',approvalId);
    if(!approval)return json(res,404,{error:'not_found'}); if(approval.status!=='pending')return json(res,409,{error:'already_decided'});
    const b=await body(req); await store.update('approvals',approvalId,{status:action==='approve'?'approved':'denied',reviewer:b.reviewer||'workspace-admin',note:b.note||'',decidedAt:nowIso()});
    const tx=await rialo.record(`approval_${action}`,store.get('approvals',approvalId));
    return json(res,200,{approval:store.get('approvals',approvalId),tx});
  }

  if(p==='/api/security/scan' && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const input=await body(req); const scan=scanForPromptInjection(input);
    if(scan.score>0) await store.add('securityEvents',{id:id('sec'),workspaceId:wsId,scan,source:'manual_scan',createdAt:nowIso()});
    return json(res,200,scan);
  }

  if(p==='/api/credentials' && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const b=await body(req); if(!b.name||!b.value)return json(res,400,{error:'name_and_value_required'});
    const item={id:id('cred'),workspaceId:wsId,name:b.name,provider:b.provider||'custom',status:'active',lastUsedAt:null,createdAt:nowIso(),encrypted:encryptCredential(b.value,vaultSecret)};
    await store.add('credentials',item); await rialo.record('credential_registered',{id:item.id,name:item.name,provider:item.provider,createdAt:item.createdAt});
    return json(res,201,{credential:redactCredential(item)});
  }

  const credentialDelete=p.match(/^\/api\/credentials\/([^/]+)$/);
  if(credentialDelete && req.method==='DELETE'){
    if(!requireAuth(req,res))return;
    const existing=getScoped('credentials',credentialDelete[1]); if(!existing)return json(res,404,{error:'not_found'});
    const item=await store.update('credentials',credentialDelete[1],{status:'revoked',revokedAt:nowIso()});
    if(!item)return json(res,404,{error:'not_found'}); await rialo.record('credential_revoked',{id:item.id}); return json(res,200,{credential:redactCredential(item)});
  }

  if(p==='/api/emergency-stop' && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const b=await body(req); const agentId=b.agentId||null;
    const incident={id:id('incident'),workspaceId:wsId,type:'emergency_stop',scope:agentId?'agent':'workspace',agentId,reason:b.reason||'Manual emergency stop',status:'active',createdAt:nowIso()};
    if(agentId){ await store.update('agents',agentId,{status:'paused'}); await store.updateMany('permits',x=>x.workspaceId===wsId&&x.agentId===agentId&&x.status==='active',{status:'revoked',revokedAt:nowIso()}); }
    else { await store.update('workspaces',wsId,{emergencyStopped:true,emergencyStoppedAt:nowIso()}); await store.updateMany('agents',x=>x.workspaceId===wsId&&x.status==='active',{status:'paused'}); await store.updateMany('permits',x=>x.workspaceId===wsId&&x.status==='active',{status:'revoked',revokedAt:nowIso()}); }
    await store.add('incidents',incident); const tx=await rialo.record('emergency_stop',incident); return json(res,200,{incident,tx});
  }

  if(p==='/api/emergency-resume' && req.method==='POST'){
    if(!requireAuth(req,res))return;
    const b=await body(req); await store.update('workspaces',wsId,{emergencyStopped:false,resumedAt:nowIso()}); await store.updateMany('agents',x=>x.workspaceId===wsId&&x.status==='paused',{status:'active'});
    const incident={id:id('incident'),workspaceId:wsId,type:'emergency_resume',scope:'workspace',reason:b.reason||'Manual resume',status:'resolved',createdAt:nowIso()};
    await store.add('incidents',incident); const tx=await rialo.record('emergency_resume',incident); return json(res,200,{incident,warning:'Previously revoked permits remain revoked and must be reissued',tx});
  }

  // Stripe webhook
  if(p==='/api/webhooks/stripe' && req.method==='POST'){
    const raw=await rawBody(req);
    try{
      const billing=new StripeBillingAdapter();
      const event=billing.verifyEvent(raw.toString(),req.headers['stripe-signature']||'');
      if(event.type==='checkout.session.completed'){
        const wsTarget=event.data?.object?.metadata?.workspace_id;
        const plan=event.data?.object?.metadata?.plan;
        if(wsTarget&&plan) await store.update('workspaces',wsTarget,{plan});
      }
      return json(res,200,{received:true,type:event.type});
    }catch(e){return json(res,400,{error:e.message});}
  }

  const verify=p.match(/^\/api\/receipts\/([^/]+)\/verify$/);
  if(verify && req.method==='GET'){ const r=getScoped('receipts',verify[1]); if(!r)return json(res,404,{error:'not_found'}); return json(res,200,{valid:verifyReceipt(r,secret),receipt:r}); }

  if(p.startsWith('/api/')) return json(res,404,{error:'not_found'});
  const file=p==='/'?'landing.html':p==='/app'?'index.html':p==='/signup'?'signup.html':p==='/account'?'account.html':p.slice(1);
  const safe=path.normalize(file).replace(/^\.\.(\/|\\|$)/,'');
  try{const data=await fs.readFile(path.join(webRoot,safe));const ext=path.extname(safe);const types={'.html':'text/html','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml'};res.writeHead(200,{'content-type':types[ext]||'application/octet-stream'});res.end(data);}catch{json(res,404,{error:'not_found'});}
}

const server=http.createServer((req,res)=>route(req,res).catch(e=>json(res,500,{error:'internal_error',message:e.message})));
server.listen(port,host,()=>console.log(`AgentPermit running on ${host}:${port}`));
