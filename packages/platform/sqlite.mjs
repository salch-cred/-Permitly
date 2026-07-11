import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { hashApiKey } from './auth.mjs';
import { createAuditEvent } from './audit.mjs';

const uid = prefix => `${prefix}_${crypto.randomUUID().replaceAll('-','')}`;
const now = () => new Date().toISOString();

export class SaaSDatabase {
  constructor(file=':memory:') { if(file!==':memory:')fs.mkdirSync(path.dirname(file),{recursive:true}); this.db=new DatabaseSync(file); this.db.exec('PRAGMA foreign_keys=ON;'); }
  migrate(sql){ this.db.exec(sql); return this; }
  close(){ this.db.close(); }
  transaction(fn){ this.db.exec('BEGIN IMMEDIATE'); try{const result=fn(this);this.db.exec('COMMIT');return result;}catch(e){this.db.exec('ROLLBACK');throw e;} }
  createTenant({organizationName,organizationSlug,workspaceName='Default',workspaceSlug='default',user}){
    return this.transaction(()=>{const orgId=uid('org'),workspaceId=uid('ws'),userId=uid('usr'),ts=now();
      this.db.prepare('INSERT INTO organizations(id,name,slug,created_at) VALUES(?,?,?,?)').run(orgId,organizationName,organizationSlug,ts);
      this.db.prepare('INSERT INTO users(id,email,password_hash,name,created_at) VALUES(?,?,?,?,?)').run(userId,user.email.toLowerCase(),user.passwordHash,user.name,ts);
      this.db.prepare('INSERT INTO workspaces(id,organization_id,name,slug,created_at) VALUES(?,?,?,?,?)').run(workspaceId,orgId,workspaceName,workspaceSlug,ts);
      this.db.prepare("INSERT INTO memberships(id,workspace_id,user_id,role,created_at) VALUES(?,?,?,'owner',?)").run(uid('mem'),workspaceId,userId,ts);
      return {organizationId:orgId,workspaceId,userId};});
  }
  findUserByEmail(email){return this.db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase());}
  membership(userId,workspaceId){return this.db.prepare('SELECT * FROM memberships WHERE user_id=? AND workspace_id=?').get(userId,workspaceId);}
  workspacesForUser(userId){return this.db.prepare('SELECT w.*,m.role,o.name organization_name,o.plan FROM workspaces w JOIN memberships m ON m.workspace_id=w.id JOIN organizations o ON o.id=w.organization_id WHERE m.user_id=?').all(userId);}
  createApiKey({workspaceId,name,keyPrefix,keyHash,role='admin',expiresAt=null}){const id=uid('key');this.db.prepare('INSERT INTO api_keys(id,workspace_id,name,key_prefix,key_hash,role,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id,workspaceId,name,keyPrefix,keyHash,role,expiresAt,now());return this.db.prepare('SELECT id,workspace_id,name,key_prefix,role,expires_at,created_at FROM api_keys WHERE id=?').get(id);}
  authenticateApiKey(raw){const hash=hashApiKey(raw);const row=this.db.prepare('SELECT * FROM api_keys WHERE key_hash=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)').get(hash,now());if(row)this.db.prepare('UPDATE api_keys SET last_used_at=? WHERE id=?').run(now(),row.id);return row||null;}
  incrementUsage(workspaceId,metric,amount=1,period=new Date().toISOString().slice(0,7)){this.db.prepare('INSERT INTO usage_counters(workspace_id,period,metric,value) VALUES(?,?,?,?) ON CONFLICT(workspace_id,period,metric) DO UPDATE SET value=value+excluded.value').run(workspaceId,period,metric,amount);return this.db.prepare('SELECT value FROM usage_counters WHERE workspace_id=? AND period=? AND metric=?').get(workspaceId,period,metric).value;}
  usage(workspaceId,period=new Date().toISOString().slice(0,7)){return Object.fromEntries(this.db.prepare('SELECT metric,value FROM usage_counters WHERE workspace_id=? AND period=?').all(workspaceId,period).map(x=>[x.metric,x.value]));}
  addWebhook({workspaceId,url,secret,events}){const id=uid('wh');this.db.prepare('INSERT INTO webhook_endpoints(id,workspace_id,url,secret,events,created_at) VALUES(?,?,?,?,?,?)').run(id,workspaceId,url,secret,JSON.stringify(events),now());return id;}
  appendAudit(input){const previous=this.db.prepare('SELECT hash FROM audit_events WHERE workspace_id=? ORDER BY id DESC LIMIT 1').get(input.workspaceId)?.hash||'GENESIS';const event=createAuditEvent({...input,previousHash:previous});this.db.prepare('INSERT INTO audit_events(workspace_id,actor_id,action,resource_type,resource_id,metadata,previous_hash,hash,timestamp) VALUES(?,?,?,?,?,?,?,?,?)').run(event.workspaceId,event.actorId,event.action,event.resourceType,event.resourceId,JSON.stringify(event.metadata),event.previousHash,event.hash,event.timestamp);return event;}
  auditEvents(workspaceId){return this.db.prepare('SELECT workspace_id workspaceId,actor_id actorId,action,resource_type resourceType,resource_id resourceId,metadata,previous_hash previousHash,hash,timestamp FROM audit_events WHERE workspace_id=? ORDER BY id').all(workspaceId).map(x=>({...x,metadata:JSON.parse(x.metadata)}));}

  // Password reset
  createResetToken({userId,tokenHash,expiresAt}){const id=uid('rst');this.db.prepare('INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').run(id,userId,tokenHash,expiresAt,now());return id;}
  getValidResetToken(tokenHash){return this.db.prepare("SELECT * FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>?").get(tokenHash,now());}
  consumeResetToken(tokenHash,newPasswordHash){const t=this.getValidResetToken(tokenHash);if(!t)return false;this.db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(newPasswordHash,t.user_id);this.db.prepare('UPDATE password_reset_tokens SET used_at=? WHERE token_hash=?').run(now(),tokenHash);return true;}

  // Team invitations
  createInvitation({workspaceId,email,role,tokenHash,expiresAt,invitedBy}){const id=uid('inv');this.db.prepare('INSERT INTO workspace_invitations(id,workspace_id,email,role,token_hash,expires_at,invited_by,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id,workspaceId,email,role||'viewer',tokenHash,expiresAt,invitedBy,now());return id;}
  getInvitationByToken(tokenHash){return this.db.prepare('SELECT * FROM workspace_invitations WHERE token_hash=? AND accepted_at IS NULL AND expires_at>?').get(tokenHash,now());}
  acceptInvitation(tokenHash,userId){const inv=this.getInvitationByToken(tokenHash);if(!inv)return null;const existing=this.db.prepare('SELECT id FROM memberships WHERE workspace_id=? AND user_id=?').get(inv.workspace_id,userId);if(existing)return null;this.db.prepare('INSERT INTO memberships(id,workspace_id,user_id,role,created_at) VALUES(?,?,?,?,?)').run(uid('mem'),inv.workspace_id,userId,inv.role,now());this.db.prepare('UPDATE workspace_invitations SET accepted_at=? WHERE id=?').run(now(),inv.id);return inv;}
  listInvitations(workspaceId){return this.db.prepare('SELECT id,email,role,expires_at,accepted_at,invited_by,created_at FROM workspace_invitations WHERE workspace_id=? ORDER BY created_at DESC').all(workspaceId);}
  listMembers(workspaceId){return this.db.prepare('SELECT u.id,u.email,u.name,m.role,m.created_at FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.workspace_id=? ORDER BY m.created_at').all(workspaceId);}
}
