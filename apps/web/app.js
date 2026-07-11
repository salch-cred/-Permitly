const token=localStorage.getItem('permitly_session')||'change-me-in-production';
const $=id=>document.getElementById(id);
const api=async(p,o={})=>{const r=await fetch('/api'+p,{...o,headers:{'content-type':'application/json','authorization':`Bearer ${token}`,...o.headers}});const j=await r.json();if(!r.ok)throw new Error(j.message||j.error||`HTTP ${r.status}`);return j};
let data={};
const pill=s=>`<span class="pill ${['active','authorized','approved','resolved'].includes(s)?'ok':['blocked','revoked','denied','critical'].includes(s)?'bad':'warn'}">${s}</span>`;
const agentName=id=>data.agents?.find(a=>a.id===id)?.name||id||'Unknown';
const toast=(message,type='ok')=>{const el=document.createElement('div');el.className=`toast ${type}`;el.textContent=message;$('toastWrap').appendChild(el);setTimeout(()=>el.remove(),3200)};
const open=id=>$(id).classList.add('open');
const close=id=>$(id).classList.remove('open');

async function load(){
  const paths=['/health','/summary','/agents','/policies','/permits','/receipts','/approvals','/credentials','/securityEvents','/incidents','/security/rules'];
  const [health,summary,agents,policies,permits,receipts,approvals,credentials,securityEvents,incidents,rules]=await Promise.all(paths.map(p=>api(p)));
  data={health,summary,agents:agents.items,policies:policies.items,permits:permits.items,receipts:receipts.items,approvals:approvals.items,credentials:credentials.items,securityEvents:securityEvents.items,incidents:incidents.items,rules:rules.items};
  render();
}

function render(){
  $('chainMode').textContent=`${data.health.rialo.mode} · ${data.health.rialo.connected?'connected':'offline'}`;
  $('approvalCount').textContent=data.summary.pendingApprovals;
  $('emergencyBanner').classList.toggle('show',data.summary.emergencyStopped);
  $('killSwitch').textContent=data.summary.emergencyStopped?'⏻ Emergency active':'⏻ Emergency stop';
  $('metrics').innerHTML=[['Active agents',data.summary.activeAgents],['Active permits',data.permits.filter(x=>x.status==='active').length],['Pending approvals',data.summary.pendingApprovals],['Security events',data.summary.securityEvents]].map(x=>`<div class="card metric"><span>${x[0]}</span><b>${x[1]}</b></div>`).join('');
  $('agentRows').innerHTML=data.agents.map(a=>`<tr><td><b>${a.name}</b></td><td>${a.type}</td><td>${pill(a.status)}</td><td><div class="risk-meter"><span style="width:${a.risk}%"></span></div>${a.risk}</td><td><button class="tiny danger" data-stop-agent="${a.id}" ${a.status==='paused'?'disabled':''}>Stop</button></td></tr>`).join('');
  $('permitRows').innerHTML=data.permits.map(p=>`<tr><td><code>${p.id}</code></td><td>${agentName(p.agentId)}</td><td>${p.scopes.join(', ')}</td><td>$${p.budgetCap}</td><td>${pill(p.status)}</td><td>${new Date(p.expiresAt).toLocaleString()}</td></tr>`).join('');
  $('policyCards').innerHTML=data.policies.map(p=>`<article class="policy-card"><div class="policy-card-top"><span class="policy-icon">◆</span>${pill(p.status)}</div><h3>${p.name}</h3><p>${p.scopes.join(' · ')}</p><div class="policy-stats"><span><b>$${p.budgetCap}</b>Total</span><span><b>$${p.maxPerAction}</b>Per action</span><span><b>${p.rateLimitPerMinute}</b>/min</span></div><div class="condition-chip">IF ${p.conditions?.[0]?.field||'request'} ${p.conditions?.[0]?.operator||'matches'} ${Array.isArray(p.conditions?.[0]?.value)?p.conditions[0].value.join(', '):p.conditions?.[0]?.value??'policy'}</div><small>Version ${p.version||1}</small></article>`).join('');
  $('receiptRows').innerHTML=data.receipts.slice().reverse().map(r=>`<tr><td>${r.id.slice(0,14)}…</td><td>${agentName(r.agentId)}</td><td>${r.scope}</td><td>$${r.amount}</td><td>${pill(r.result)}</td><td><code>${r.hash.slice(0,10)}…</code></td></tr>`).join('')||'<tr><td colspan="6">No receipts yet.</td></tr>';
  $('permitMini').innerHTML=data.permits.filter(p=>p.status==='active').slice(0,4).map(p=>`<div class="notice"><b>${agentName(p.agentId)}</b> · ${p.scopes.join(', ')} · $${p.budgetCap}</div>`).join('')||'<div class="muted">No active permits</div>';
  $('decisionMini').innerHTML=data.receipts.slice(-4).reverse().map(r=>`<div class="notice">${pill(r.result)} ${r.scope}</div>`).join('')||'<div class="muted">No decisions yet</div>';
  $('approvalCards').innerHTML=data.approvals.slice().reverse().map(a=>`<article class="approval-card"><div><div class="approval-title">${agentName(a.agentId)} requests <b>${a.action?.scope||'action'}</b></div><div class="muted">${a.reason}</div><div class="approval-meta"><span>Target: ${a.action?.target||'—'}</span><span>Amount: $${a.action?.amount||0}</span><span>${new Date(a.createdAt).toLocaleString()}</span></div></div><div class="approval-actions">${a.status==='pending'?`<button class="tiny approve" data-approve="${a.id}">Approve</button><button class="tiny danger" data-deny="${a.id}">Deny</button>`:pill(a.status)}</div></article>`).join('')||'<div class="empty-state">No approval requests.</div>';
  $('credentialRows').innerHTML=data.credentials.map(c=>`<tr><td><b>${c.name}</b></td><td>${c.provider}</td><td>${pill(c.status)}</td><td>${c.configured?'Encrypted':'Missing'}</td><td>${new Date(c.createdAt).toLocaleDateString()}</td><td><button class="tiny danger" data-revoke-credential="${c.id}" ${c.status==='revoked'?'disabled':''}>Revoke</button></td></tr>`).join('')||'<tr><td colspan="6">No credentials stored.</td></tr>';
  $('firewallRules').innerHTML=data.rules.map(r=>`<div class="rule-row"><span>${r.label}</span><b>+${r.weight}</b></div>`).join('');
  $('securityEvents').innerHTML=data.securityEvents.slice(-8).reverse().map(e=>`<div class="event-row"><div class="risk-dot ${e.scan.level}"></div><div><b>${e.scan.level.toUpperCase()} · score ${e.scan.score}</b><div class="muted">${e.scan.matches.map(x=>x.label).join(', ')}</div></div><time>${new Date(e.createdAt).toLocaleString()}</time></div>`).join('')||'<div class="empty-state">No threats detected.</div>';
  $('riskAlerts').innerHTML=data.agents.filter(a=>a.risk>50||a.status==='paused').map(a=>`<div class="notice"><b>${a.name}</b> ${pill(a.status)}<br><span class="muted">Risk score ${a.risk}; review access and budget.</span></div>`).join('')||'<div class="notice">No high-risk agents.</div>';
  $('incidentRows').innerHTML=data.incidents.slice().reverse().map(i=>`<div class="event-row"><div class="risk-dot ${i.type==='emergency_stop'?'critical':'low'}"></div><div><b>${i.type.replaceAll('_',' ')}</b><div class="muted">${i.reason}</div></div><time>${new Date(i.createdAt).toLocaleString()}</time></div>`).join('')||'<div class="empty-state">No incidents recorded.</div>';
  $('agent').innerHTML=data.agents.map(a=>`<option value="${a.id}">${a.name}</option>`).join('');
  bindDynamicActions();
}

function bindDynamicActions(){
  document.querySelectorAll('[data-approve]').forEach(b=>b.onclick=()=>decideApproval(b.dataset.approve,'approve'));
  document.querySelectorAll('[data-deny]').forEach(b=>b.onclick=()=>decideApproval(b.dataset.deny,'deny'));
  document.querySelectorAll('[data-stop-agent]').forEach(b=>b.onclick=()=>stopAgent(b.dataset.stopAgent));
  document.querySelectorAll('[data-revoke-credential]').forEach(b=>b.onclick=()=>revokeCredential(b.dataset.revokeCredential));
}
async function decideApproval(id,action){try{await api(`/approvals/${id}/${action}`,{method:'POST',body:JSON.stringify({reviewer:'Mahammad Salman'})});toast(`Request ${action}d`);await load()}catch(e){toast(e.message,'bad')}}
async function stopAgent(agentId){if(!confirm(`Emergency stop ${agentName(agentId)}? Active permits will be revoked.`))return;try{await api('/emergency-stop',{method:'POST',body:JSON.stringify({agentId,reason:'Stopped from agent directory'})});toast(`${agentName(agentId)} stopped`);await load()}catch(e){toast(e.message,'bad')}}
async function revokeCredential(id){if(!confirm('Revoke this credential?'))return;try{await api(`/credentials/${id}`,{method:'DELETE'});toast('Credential revoked');await load()}catch(e){toast(e.message,'bad')}}

const panelSubtitles={overview:'Live permits, policy decisions and Rialo receipts.',agents:'Identity, status and risk for every autonomous worker.',permits:'Time-boxed capabilities issued to agents.',policies:'Build reusable rules without writing code.',approvals:'Human review for high-risk or high-value actions.',vault:'Encrypted service credentials agents never see.',security:'Detect prompt injection before tools execute.',receipts:'Signed and hash-chained proof of every decision.',risk:'Incidents, anomalies and emergency controls.'};
document.querySelectorAll('.navlink').forEach(n=>n.onclick=()=>{document.querySelectorAll('.navlink,.panel').forEach(x=>x.classList.remove('active'));n.classList.add('active');$(n.dataset.panel).classList.add('active');$('title').textContent=n.childNodes[0].textContent.trim();$('subtitle').textContent=panelSubtitles[n.dataset.panel]});
document.querySelectorAll('[data-close]').forEach(b=>b.onclick=()=>close(b.dataset.close));
$('newPermit').onclick=()=>open('permitDrawer');$('newPolicy').onclick=()=>open('policyDrawer');$('newCredential').onclick=()=>open('credentialDrawer');$('killSwitch').onclick=()=>open('killDrawer');

$('permitForm').onsubmit=async e=>{e.preventDefault();try{await api('/permits',{method:'POST',body:JSON.stringify({agentId:$('agent').value,scopes:$('scopes').value.split(',').map(x=>x.trim()),budgetCap:+$('budget').value,maxPerAction:+$('perAction').value,requireHumanAbove:+$('human').value,expiresAt:new Date(Date.now()+$('hours').value*3600000).toISOString()})});close('permitDrawer');toast('Permit issued and anchored');await load()}catch(e){toast(e.message,'bad')}};
function updatePolicyPreview(){const value=$('conditionValue').value;$('policyPreview').innerHTML=`<span>ALLOW</span> ${$('policyScopes').value||'scope'} <b>IF</b> ${$('conditionField').value} ${$('conditionOperator').value} ${value||'value'} <b>AND</b> amount ≤ $${$('policyPerAction').value||0}`}
['policyScopes','conditionField','conditionOperator','conditionValue','policyPerAction'].forEach(id=>$(id).oninput=updatePolicyPreview);updatePolicyPreview();
$('policyForm').onsubmit=async e=>{e.preventDefault();let value=$('conditionValue').value;if($('conditionOperator').value==='in')value=value.split(',').map(x=>x.trim());else if(!Number.isNaN(Number(value))&&value!=='')value=Number(value);try{await api('/policies',{method:'POST',body:JSON.stringify({name:$('policyName').value,scopes:$('policyScopes').value.split(',').map(x=>x.trim()),budgetCap:+$('policyBudget').value,maxPerAction:+$('policyPerAction').value,requireHumanAbove:+$('policyHuman').value,rateLimitPerMinute:+$('policyRate').value,conditions:[{field:$('conditionField').value,operator:$('conditionOperator').value,value}]})});close('policyDrawer');toast('Policy published to Rialo adapter');e.target.reset();await load()}catch(e){toast(e.message,'bad')}};
$('credentialForm').onsubmit=async e=>{e.preventDefault();const type=$('credentialType').value;const value=type==='bearer'?{type,token:$('credentialValue').value}:{type,header:$('credentialHeader').value,value:$('credentialValue').value};try{await api('/credentials',{method:'POST',body:JSON.stringify({name:$('credentialName').value,provider:$('credentialProvider').value,value})});close('credentialDrawer');toast('Credential encrypted and saved');e.target.reset();await load()}catch(e){toast(e.message,'bad')}};
$('scanButton').onclick=async()=>{try{const r=await api('/security/scan',{method:'POST',body:JSON.stringify({content:$('scanInput').value})});$('scanResult').innerHTML=`<div class="scan-result ${r.level}"><b>${r.level.toUpperCase()} RISK · ${r.score}/100</b><p>${r.matches.length?r.matches.map(x=>x.label).join(' · '):'No injection patterns detected.'}</p><span>Recommendation: ${r.recommendation}</span></div>`;await load()}catch(e){toast(e.message,'bad')}};
$('confirmKill').onclick=async()=>{try{await api('/emergency-stop',{method:'POST',body:JSON.stringify({reason:$('killReason').value})});close('killDrawer');toast('Workspace emergency stop activated','bad');await load()}catch(e){toast(e.message,'bad')}};
$('resumeWorkspace').onclick=async()=>{if(!confirm('Resume agents? Revoked permits will remain revoked.'))return;try{await api('/emergency-resume',{method:'POST',body:JSON.stringify({reason:'Incident reviewed by workspace admin'})});toast('Workspace resumed');await load()}catch(e){toast(e.message,'bad')}};
load().catch(e=>toast(`Dashboard failed: ${e.message}`,'bad'));
