# SDKs

## JavaScript / TypeScript

```js
import { AgentPermitClient } from './packages/sdk-js/index.mjs';
const client = new AgentPermitClient({ apiKey: process.env.AGENTPERMIT_API_KEY });
const result = await client.authorize({
  permitId: 'permit_123',
  agentId: 'agent_deploybot',
  scope: 'deploy:production',
  target: 'production',
  amount: 0,
  input: 'Deploy release 2.1.0'
});
if (result.evaluation.decision !== 'authorized') throw new Error(result.evaluation.reason);
```

## Python

```python
from agentpermit import AgentPermit
client = AgentPermit(api_key=os.environ['AGENTPERMIT_API_KEY'])
result = client.authorize(
    permitId='permit_123',
    agentId='agent_deploybot',
    scope='deploy:production',
    target='production',
    amount=0,
    input='Deploy release 2.1.0'
)
```

API keys are workspace-scoped and should be stored in a secret manager. Never put a live key in agent prompts or source control.
