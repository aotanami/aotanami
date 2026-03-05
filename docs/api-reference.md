# API Reference

Zelyo Operator exposes a REST API that powers the embedded dashboard and enables external integrations.

## Base URL

```
http://<zelyo-operator-service>:8080/api/v1
```

## Authentication

The API uses Kubernetes ServiceAccount token authentication. Include the bearer token in requests:

```bash
TOKEN=$(kubectl create token zelyo-operator -n zelyo-system)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/health
```

## Endpoints

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/readyz` | Readiness check |

### Incidents

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/incidents` | List active incidents |
| `GET` | `/api/v1/incidents/:id` | Get incident details |
| `POST` | `/api/v1/incidents/:id/acknowledge` | Acknowledge an incident |

### Scans

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/scans` | List scan history |
| `POST` | `/api/v1/scans/trigger` | Trigger an ad-hoc scan |
| `GET` | `/api/v1/scans/:id/report` | Get scan report |

### Findings

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/findings` | List findings (filterable by severity, category) |
| `GET` | `/api/v1/findings/summary` | Aggregated findings summary |

### Cost

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/costs` | Current cost analysis |
| `GET` | `/api/v1/costs/recommendations` | Rightsizing recommendations |

### Drift

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/drift` | Config drift status |
| `GET` | `/api/v1/drift/:namespace` | Drift details for a namespace |

### Token Usage

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/token-usage` | Current LLM token consumption |

### Notifications

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/notifications` | Notification history |

### Clusters (Multi-Cluster)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/clusters` | List federated clusters |
| `GET` | `/api/v1/clusters/:name/status` | Cluster status |

## Response Format

All responses follow a consistent JSON envelope:

```json
{
  "data": { ... },
  "metadata": {
    "page": 1,
    "pageSize": 20,
    "total": 100
  }
}
```

Error responses:

```json
{
  "error": {
    "code": 404,
    "message": "Resource not found"
  }
}
```

## OpenAPI Specification

The full OpenAPI spec is served at:

```
GET /api/v1/openapi.json
```
