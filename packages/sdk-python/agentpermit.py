"""Dependency-free AgentPermit Python SDK."""
import json
import urllib.request
import urllib.error

class AgentPermitError(Exception):
    def __init__(self, message, status=None, details=None):
        super().__init__(message); self.status=status; self.details=details

class AgentPermit:
    def __init__(self, api_key, base_url="https://api.agentpermit.com", timeout=10):
        self.api_key=api_key; self.base_url=base_url.rstrip("/"); self.timeout=timeout
    def request(self, path, method="GET", body=None):
        data=None if body is None else json.dumps(body).encode()
        req=urllib.request.Request(self.base_url+path,data=data,method=method,headers={"Authorization":f"Bearer {self.api_key}","Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(req,timeout=self.timeout) as response: return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            details=json.loads(exc.read() or b"{}")
            raise AgentPermitError(details.get("message") or details.get("error") or "AgentPermit request failed",exc.code,details) from exc
    def authorize(self, **action): return self.request("/api/actions/authorize","POST",action)
    def issue_permit(self, **permit): return self.request("/api/permits","POST",permit)
    def revoke_permit(self, permit_id): return self.request(f"/api/permits/{permit_id}/revoke","POST",{})
    def approvals(self): return self.request("/api/approvals")
    def decide_approval(self, approval_id, decision, note=""): return self.request(f"/api/approvals/{approval_id}/{decision}","POST",{"note":note})
    def verify_receipt(self, receipt_id): return self.request(f"/api/receipts/{receipt_id}/verify")
