import fs from 'node:fs/promises';
import path from 'node:path';
import { id } from '../../packages/core/policy.mjs';

const seed = () => {
  const now = Date.now();
  const agents = [
    ['DeployBot','devops'], ['Support Triage','support'], ['Research Scout','research'],
    ['Billing Assistant','finance'], ['Vendor Bot','procurement']
  ].map(([name,type], i) => ({ id:`agent_${i+1}`, workspaceId:'ws_demo', name, type, status:i===2?'review':'active', risk:i===2?82:18+i*7, createdAt:new Date(now-86400000*7).toISOString() }));
  const policies = [
    { id:'pol_deploy', name:'Standard deploy window', scopes:['deploy:*'], budgetCap:1000, maxPerAction:500, rateLimitPerMinute:20, requireHumanAbove:450, conditions:[{field:'target',operator:'in',value:['staging','production']}] },
    { id:'pol_support', name:'Support operations', scopes:['tickets:*','email:send'], budgetCap:100, maxPerAction:50, rateLimitPerMinute:60, requireHumanAbove:40, conditions:[{field:'amount',operator:'lte',value:50}] },
    { id:'pol_research', name:'Research budget guard', scopes:['web:read','dataset:purchase'], budgetCap:400, maxPerAction:150, rateLimitPerMinute:30, requireHumanAbove:100, conditions:[{field:'promptRisk',operator:'lt',value:45}] }
  ].map(p => ({...p, workspaceId:'ws_demo', status:'active', version:1, createdAt:new Date(now-86400000*3).toISOString()}));
  const permits = [
    {id:'permit_deploy',agentId:'agent_1',policyId:'pol_deploy',scopes:['deploy:*'],budgetCap:1000,maxPerAction:500,rateLimitPerMinute:20,requireHumanAbove:450,allowedTargets:['staging','production']},
    {id:'permit_support',agentId:'agent_2',policyId:'pol_support',scopes:['tickets:*','email:send'],budgetCap:100,maxPerAction:50,rateLimitPerMinute:60,requireHumanAbove:40,allowedTargets:[]},
    {id:'permit_research',agentId:'agent_3',policyId:'pol_research',scopes:['web:read','dataset:purchase'],budgetCap:400,maxPerAction:150,rateLimitPerMinute:30,requireHumanAbove:100,allowedTargets:[]}
  ].map(p => ({...p,workspaceId:'ws_demo',status:'active',issuedAt:new Date(now-3600000).toISOString(),expiresAt:new Date(now+86400000).toISOString()}));
  const approvals = [{
    id:'approval_demo', workspaceId:'ws_demo', permitId:'permit_research', agentId:'agent_3', receiptId:null,
    action:{scope:'dataset:purchase',target:'market-data-provider',amount:120}, status:'pending', reason:'Amount requires human approval above 100', createdAt:new Date(now-1200000).toISOString()
  }];
  return {
    workspaces:[{id:'ws_demo',name:'AgentPermit Demo', emergencyStopped:false}], agents, policies, permits,
    receipts:[], approvals, credentials:[], securityEvents:[], incidents:[]
  };
};

const collections = ['workspaces','agents','policies','permits','receipts','approvals','credentials','securityEvents','incidents'];

export class Store {
  constructor(dataDir='./data') { this.file = path.join(dataDir,'store.json'); this.data=null; }
  async init(){
    await fs.mkdir(path.dirname(this.file),{recursive:true});
    try { this.data=JSON.parse(await fs.readFile(this.file,'utf8')); }
    catch { this.data=seed(); }
    for (const key of collections) if (!Array.isArray(this.data[key])) this.data[key]=[];
    if (!this.data.workspaces.length) this.data.workspaces=seed().workspaces;
    await this.save();
    return this;
  }
  async save(){ await fs.writeFile(this.file,JSON.stringify(this.data,null,2)); }
  list(k){ return this.data[k] || []; }
  get(k,id){ return this.list(k).find(x=>x.id===id); }
  async add(k,value){ if(!this.data[k])this.data[k]=[]; this.data[k].push(value); await this.save(); return value; }
  async update(k,id,patch){ const item=this.get(k,id); if(!item)return null; Object.assign(item,patch); await this.save(); return item; }
  async updateMany(k,predicate,patch){ const changed=[]; for(const item of this.list(k)){ if(predicate(item)){Object.assign(item,typeof patch==='function'?patch(item):patch);changed.push(item);} } await this.save(); return changed; }
  makeId(prefix){ return id(prefix); }
}
