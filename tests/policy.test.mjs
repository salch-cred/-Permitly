import test from 'node:test'; import assert from 'node:assert/strict';
import { evaluatePermit, scopeAllows } from '../packages/core/policy.mjs';
const permit={id:'p',workspaceId:'w',agentId:'a',status:'active',expiresAt:'2099-01-01T00:00:00.000Z',scopes:['deploy:*'],budgetCap:100,maxPerAction:60,requireHumanAbove:50,rateLimitPerMinute:3,allowedTargets:['staging']};
test('wildcard scope',()=>assert.equal(scopeAllows('deploy:*','deploy:staging'),true));
test('authorizes valid action',()=>assert.equal(evaluatePermit({permit,request:{agentId:'a',scope:'deploy:staging',target:'staging',amount:20}}).decision,'authorized'));
test('blocks wrong scope',()=>assert.equal(evaluatePermit({permit,request:{agentId:'a',scope:'wallet:send',amount:1}}).code,'scope_denied'));
test('escalates human threshold',()=>assert.equal(evaluatePermit({permit,request:{agentId:'a',scope:'deploy:staging',target:'staging',amount:55}}).decision,'escalated'));
test('blocks expired',()=>assert.equal(evaluatePermit({permit:{...permit,expiresAt:'2020-01-01T00:00:00.000Z'},request:{agentId:'a',scope:'deploy:staging'}}).code,'permit_expired'));
