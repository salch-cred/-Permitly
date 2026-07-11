import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { hashPassword, verifyPassword, createSession, verifySession, createApiKey } from '../packages/platform/auth.mjs';
import { can } from '../packages/platform/rbac.mjs';
import { createAuditEvent, verifyAuditChain } from '../packages/platform/audit.mjs';
import { signWebhook, verifyWebhook } from '../packages/platform/webhooks.mjs';
import { SlidingWindowRateLimiter } from '../packages/platform/rate-limit.mjs';
import { enforcePlan } from '../packages/platform/billing.mjs';
import { SaaSDatabase } from '../packages/platform/sqlite.mjs';
import { JobQueue } from '../packages/platform/queue.mjs';

const schema=fs.readFileSync(new URL('../database/sqlite/001_init.sql',import.meta.url),'utf8');

test('passwords and sessions authenticate safely',async()=>{const hash=await hashPassword('correct-horse-battery-staple');assert.equal(await verifyPassword('correct-horse-battery-staple',hash),true);assert.equal(await verifyPassword('wrong-password-here',hash),false);const token=createSession({sub:'u1',workspaceId:'w1'},'secret',60);assert.equal(verifySession(token,'secret').sub,'u1');assert.equal(verifySession(token,'wrong'),null);});
test('RBAC enforces roles',()=>{assert.equal(can('owner','anything:write'),true);assert.equal(can('approver','approvals:write'),true);assert.equal(can('viewer','credentials:write'),false);});
test('audit chain detects tampering',()=>{const a=createAuditEvent({workspaceId:'w',actorId:'u',action:'create',resourceType:'permit',resourceId:'p'});const b=createAuditEvent({workspaceId:'w',actorId:'u',action:'revoke',resourceType:'permit',resourceId:'p',previousHash:a.hash});assert.equal(verifyAuditChain([a,b]),true);assert.equal(verifyAuditChain([a,{...b,action:'hide'}]),false);});
test('webhook signatures verify',()=>{const payload=JSON.stringify({type:'permit.created'});const signed=signWebhook(payload,'whsec',Math.floor(Date.now()/1000));assert.equal(verifyWebhook(payload,signed.header,'whsec'),true);assert.equal(verifyWebhook(payload+'x',signed.header,'whsec'),false);});
test('rate limiter blocks excess requests',()=>{const limiter=new SlidingWindowRateLimiter({windowMs:1000,max:2});assert.equal(limiter.consume('k',0).allowed,true);assert.equal(limiter.consume('k',1).allowed,true);assert.equal(limiter.consume('k',2).allowed,false);});
test('plan limits are enforced',()=>{assert.equal(enforcePlan('developer',{agents:2},'agents').allowed,true);assert.equal(enforcePlan('developer',{agents:3},'agents').allowed,false);});
test('multi-tenant database isolates membership, keys, usage and audit',async()=>{const db=new SaaSDatabase(':memory:').migrate(schema);const passwordHash=await hashPassword('correct-horse-battery-staple');const tenant=db.createTenant({organizationName:'Acme',organizationSlug:'acme',user:{email:'owner@acme.test',name:'Owner',passwordHash}});assert.equal(db.workspacesForUser(tenant.userId).length,1);const generated=createApiKey('ap_test');db.createApiKey({workspaceId:tenant.workspaceId,name:'test',keyPrefix:generated.prefix,keyHash:generated.hash});assert.equal(db.authenticateApiKey(generated.raw).workspace_id,tenant.workspaceId);assert.equal(db.incrementUsage(tenant.workspaceId,'decisions'),1);db.appendAudit({workspaceId:tenant.workspaceId,actorId:tenant.userId,action:'workspace.created',resourceType:'workspace',resourceId:tenant.workspaceId});assert.equal(verifyAuditChain(db.auditEvents(tenant.workspaceId)),true);const q=new JobQueue(db.db);const job=q.enqueue('webhook',{event:'x'});assert.equal(q.claim().id,job);q.complete(job);db.close();});
