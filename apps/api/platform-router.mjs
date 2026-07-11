import fs from 'node:fs';
import path from 'node:path';
import { SaaSDatabase } from '../../packages/platform/sqlite.mjs';
import { hashPassword, verifyPassword, createSession, verifySession, createApiKey } from '../../packages/platform/auth.mjs';
import { requirePermission } from '../../packages/platform/rbac.mjs';
import { verifyAuditChain } from '../../packages/platform/audit.mjs';
import { PLANS, StripeBillingAdapter } from '../../packages/platform/billing.mjs';

export function createPlatformRouter({ databasePath = process.env.SAAS_DATABASE_PATH || './data/saas.db', sessionSecret = process.env.SESSION_SECRET || 'development-session-secret-change-me' } = {}) {
  const db = new SaaSDatabase(databasePath);
  const billing = new StripeBillingAdapter();
  const migration = fs.readFileSync(path.resolve('database/sqlite/001_init.sql'),'utf8');
  db.migrate(migration);

  async function context(req) {
    const raw = String(req.headers.authorization || '').replace(/^Bearer\s+/i,'');
    if (!raw) return null;
    if (raw.startsWith('ap_')) {
      const key=db.authenticateApiKey(raw); if(!key)return null;
      return { userId:`api-key:${key.id}`,workspaceId:key.workspace_id,role:key.role,apiKeyId:key.id };
    }
    const session=verifySession(raw,sessionSecret); if(!session)return null;
    const membership=db.membership(session.sub,session.workspaceId); if(!membership)return null;
    return {userId:session.sub,workspaceId:session.workspaceId,role:membership.role};
  }

  async function handle({req,res,path:route,json,readBody}) {
    if (!route.startsWith('/api/v1/')) return false;
    try {
      if(route==='/api/v1/auth/register'&&req.method==='POST'){
        const b=await readBody(req); const passwordHash=await hashPassword(b.password);
        const tenant=db.createTenant({organizationName:b.organizationName,organizationSlug:b.organizationSlug,workspaceName:b.workspaceName||'Production',workspaceSlug:b.workspaceSlug||'production',user:{email:b.email,name:b.name,passwordHash}});
        const token=createSession({sub:tenant.userId,workspaceId:tenant.workspaceId},sessionSecret,86400);
        db.appendAudit({workspaceId:tenant.workspaceId,actorId:tenant.userId,action:'tenant.created',resourceType:'workspace',resourceId:tenant.workspaceId});
        json(res,201,{...tenant,token}); return true;
      }
      if(route==='/api/v1/auth/login'&&req.method==='POST'){
        const b=await readBody(req); const user=db.findUserByEmail(b.email);
        if(!user||!await verifyPassword(b.password,user.password_hash)){json(res,401,{error:'invalid_credentials'});return true;}
        const workspaces=db.workspacesForUser(user.id); if(!workspaces.length){json(res,403,{error:'no_workspace'});return true;}
        const selected=workspaces.find(x=>x.id===b.workspaceId)||workspaces[0];
        const token=createSession({sub:user.id,workspaceId:selected.id},sessionSecret,86400);
        json(res,200,{token,user:{id:user.id,email:user.email,name:user.name},workspace:selected}); return true;
      }
      if(route==='/api/v1/billing/plans'&&req.method==='GET'){json(res,200,{plans:PLANS});return true;}
      const ctx=await context(req); if(!ctx){json(res,401,{error:'authentication_required'});return true;}
      if(route==='/api/v1/me'&&req.method==='GET'){const user=ctx.userId.startsWith('api-key:')?null:db.db.prepare('SELECT id,email,name,email_verified,created_at FROM users WHERE id=?').get(ctx.userId);json(res,200,{user,context:ctx,workspaces:user?db.workspacesForUser(user.id):[]});return true;}
      if(route==='/api/v1/api-keys'&&req.method==='POST'){requirePermission(ctx,'members:*');const b=await readBody(req);const generated=createApiKey(b.environment==='test'?'ap_test':'ap_live');const key=db.createApiKey({workspaceId:ctx.workspaceId,name:b.name||'API key',keyPrefix:generated.prefix,keyHash:generated.hash,role:b.role||'admin',expiresAt:b.expiresAt||null});db.appendAudit({workspaceId:ctx.workspaceId,actorId:ctx.userId,action:'api_key.created',resourceType:'api_key',resourceId:key.id,metadata:{prefix:key.key_prefix,role:key.role}});json(res,201,{key:{...key,secret:generated.raw}});return true;}
      if(route==='/api/v1/usage'&&req.method==='GET'){json(res,200,{usage:db.usage(ctx.workspaceId)});return true;}
      if(route==='/api/v1/billing/checkout'&&req.method==='POST'){requirePermission(ctx,'billing:read');const b=await readBody(req);const user=ctx.userId.startsWith('api-key:')?null:db.db.prepare('SELECT email FROM users WHERE id=?').get(ctx.userId);if(!user)throw Object.assign(new Error('User session required for checkout'),{status:403});const checkout=await billing.createCheckout({customerEmail:user.email,workspaceId:ctx.workspaceId,plan:b.plan,successUrl:b.successUrl,cancelUrl:b.cancelUrl});json(res,201,{id:checkout.id,url:checkout.url});return true;}
      if(route==='/api/v1/usage/decision'&&req.method==='POST'){requirePermission(ctx,'permits:*');json(res,200,{value:db.incrementUsage(ctx.workspaceId,'decisions',1)});return true;}
      if(route==='/api/v1/webhooks'&&req.method==='POST'){requirePermission(ctx,'members:*');const b=await readBody(req);const target=new URL(b.url);if(target.protocol!=='https:')throw Object.assign(new Error('Webhook URL must use HTTPS'),{status:400});const id=db.addWebhook({workspaceId:ctx.workspaceId,url:b.url,secret:b.secret,events:b.events||['*']});db.appendAudit({workspaceId:ctx.workspaceId,actorId:ctx.userId,action:'webhook.created',resourceType:'webhook',resourceId:id,metadata:{url:b.url,events:b.events||['*']}});json(res,201,{id});return true;}
      if(route==='/api/v1/audit'&&req.method==='GET'){requirePermission(ctx,'audit:read');const events=db.auditEvents(ctx.workspaceId);json(res,200,{items:events,chainValid:verifyAuditChain(events)});return true;}
      json(res,404,{error:'not_found'}); return true;
    } catch(error){json(res,error.status||400,{error:error.message});return true;}
  }
  return {db,handle,context};
}
