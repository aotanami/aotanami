# Notification Integrations

Zelyo Operator supports sending alerts to multiple notification channels simultaneously. Each channel is configured via a `NotificationChannel` CRD.

## Slack

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: slack-security
spec:
  type: slack
  credentialSecret: slack-bot-token   # Secret key: "token"
  severityFilter: high
  slack:
    channel: "#security-alerts"
  rateLimit:
    maxPerHour: 30
```

**Secret format**: `kubectl create secret generic slack-bot-token --from-literal=token=xoxb-xxx`

## Microsoft Teams

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: teams-ops
spec:
  type: msteams
  credentialSecret: teams-webhook
  msTeams:
    webhookURLKey: webhook-url
```

**Secret format**: `kubectl create secret generic teams-webhook --from-literal=webhook-url=https://outlook.office.com/webhook/xxx`

## PagerDuty

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: pagerduty-critical
spec:
  type: pagerduty
  credentialSecret: pagerduty-key
  severityFilter: critical
  pagerDuty:
    routingKeyKey: routing-key
    defaultSeverity: critical
```

## AlertManager

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: alertmanager
spec:
  type: alertmanager
  credentialSecret: alertmanager-auth   # Optional
  alertManager:
    endpoint: http://alertmanager.monitoring:9093
```

## Telegram

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: telegram-alerts
spec:
  type: telegram
  credentialSecret: telegram-bot    # Secret key: "token"
  telegram:
    chatID: "-1001234567890"
```

## WhatsApp

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: whatsapp-oncall
spec:
  type: whatsapp
  credentialSecret: whatsapp-creds  # Secret keys: "token", "phone-number-id"
  whatsApp:
    phoneNumber: "+1234567890"
```

## Webhook (Generic)

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: custom-webhook
spec:
  type: webhook
  credentialSecret: webhook-auth    # Optional
  webhook:
    url: https://api.example.com/zelyo-operator-alerts
    headers:
      X-Source: zelyo-operator
```

## Email

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: email-team
spec:
  type: email
  credentialSecret: smtp-creds      # Secret keys: "username", "password"
  email:
    recipients: ["team@company.com", "oncall@company.com"]
    smtpHost: smtp.gmail.com
    smtpPort: 587
    fromAddress: zelyo-operator@company.com
```

## Rate Limiting

All channels support rate limiting to prevent alert storms:

```yaml
rateLimit:
  maxPerHour: 60          # Max notifications per hour (0 = unlimited)
  aggregateSeconds: 30    # Group alerts within this window
```
