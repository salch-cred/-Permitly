export class AgentPermitClient {
  constructor({apiKey,baseUrl='https://api.agentpermit.com',fetchImpl=fetch}){this.apiKey=apiKey;this.baseUrl=baseUrl.replace(/\/$/,'');this.fetch=fetchImpl;}
  async request(path,{method='GET',body,headers={}}={}){const r=await this.fetch(this.baseUrl+path,{method,headers:{authorization:`Bearer ${this.apiKey}`,'content-type':'application/json',...headers},body:body===undefined?undefined:JSON.stringify(body)});const j=await r.json();if(!r.ok)throw new AgentPermitError(j.message||j.error||'AgentPermit request failed',r.status,j);return j;}
  authorize(input){return this.request('/api/actions/authorize',{method:'POST',body:input});}
  issuePermit(input){return this.request('/api/permits',{method:'POST',body:input});}
  revokePermit(id){return this.request(`/api/permits/${encodeURIComponent(id)}/revoke`,{method:'POST',body:{}});}
  approvals(){return this.request('/api/approvals');}
  decideApproval(id,decision,note=''){return this.request(`/api/approvals/${encodeURIComponent(id)}/${decision}`,{method:'POST',body:{note}});}
  verifyReceipt(id){return this.request(`/api/receipts/${encodeURIComponent(id)}/verify`);}
}
export class AgentPermitError extends Error{constructor(message,status,details){super(message);this.name='AgentPermitError';this.status=status;this.details=details;}}
