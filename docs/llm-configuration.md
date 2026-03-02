# LLM Configuration

Aotanami uses LLMs (Large Language Models) for intelligent diagnosis and remediation. You bring your own API keys.

## Supported Providers

| Provider | Config Value | Models |
|---|---|---|
| [OpenRouter](https://openrouter.ai) | `openrouter` | Any model available on OpenRouter |
| [OpenAI](https://openai.com) | `openai` | GPT-4o, GPT-4o-mini, etc. |
| [Anthropic](https://anthropic.com) | `anthropic` | Claude Sonnet, Claude Haiku, etc. |
| [Azure OpenAI](https://azure.microsoft.com/en-us/products/ai-services/openai-service) | `azure-openai` | Deployed models |
| [Ollama](https://ollama.com) | `ollama` | Local models |
| Custom | `custom` | Any OpenAI-compatible API |

## Configuration

### Via AotanamiConfig CRD

```yaml
apiVersion: aotanami.com/v1alpha1
kind: AotanamiConfig
metadata:
  name: default
spec:
  llm:
    provider: openrouter
    model: "anthropic/claude-sonnet-4-20250514"
    apiKeySecret: aotanami-llm
    temperature: "0.1"
    maxTokensPerRequest: 4096
  tokenBudget:
    hourlyTokenLimit: 50000
    dailyTokenLimit: 500000
    monthlyTokenLimit: 10000000
    alertThresholdPercent: 80
    enableCaching: true
    batchingEnabled: true
```

### API Key Secret

```bash
kubectl create secret generic aotanami-llm \
  --namespace aotanami-system \
  --from-literal=api-key=<YOUR_API_KEY>
```

## Cost Optimization

Aotanami is designed to minimize LLM API costs:

### 1. Local Triage First
Most events are handled locally without any LLM call. The correlator deduplicates, scores severity, and filters before escalation. Only novel, complex incidents reach the LLM.

### 2. Prompt Caching
Repeated analysis patterns use cached prompt templates. If the same type of issue recurs, the cached response is reused.

### 3. Structured Output
All LLM calls use JSON structured output schemas, getting machine-parseable responses on the first attempt without re-prompting.

### 4. Batching
Multiple related findings are batched into a single LLM call, reducing per-request overhead.

### 5. Token Budgets
Configure hard limits on token consumption:

| Budget | Default | Description |
|---|---|---|
| `hourlyTokenLimit` | 50,000 | Max tokens per hour |
| `dailyTokenLimit` | 500,000 | Max tokens per day |
| `monthlyTokenLimit` | 10,000,000 | Max tokens per month |

When a budget is exhausted, Aotanami falls back to rule-based detection only (no LLM) until the budget resets.

### 6. Monitor Usage
Check token consumption via:

```bash
kubectl get aotanamiconfigs default -o jsonpath='{.status.tokenUsage}'
```

Or via the dashboard's **LLM Usage** view.

## Recommended Models

| Use Case | Recommended | Cost |
|---|---|---|
| Production (best quality) | `anthropic/claude-sonnet-4-20250514` | $$ |
| Production (cost-effective) | `anthropic/claude-haiku` | $ |
| Development/Testing | `ollama` (local) | Free |
