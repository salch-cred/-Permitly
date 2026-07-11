import test from 'node:test'; import assert from 'node:assert/strict';
import {createReceipt,verifyReceipt} from '../packages/core/receipts.mjs';
const secret='test-secret';
const r=createReceipt({request:{agentId:'a',scope:'x',amount:2},permit:{id:'p',workspaceId:'w'},evaluation:{decision:'authorized',code:'ok',reason:'ok'},previousHash:'GENESIS',secret});
test('valid receipt verifies',()=>assert.equal(verifyReceipt(r,secret),true));
test('tampered receipt fails',()=>assert.equal(verifyReceipt({...r,amount:99},secret),false));
