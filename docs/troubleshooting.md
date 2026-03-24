# Troubleshooting

This guide helps you resolve common issues encountered while setting up or running the Zelyo Operator.

## Webhooks

### Error: "the server could not find the requested resource"
When applying a `SecurityPolicy`, you may encounter an error like this:
`Error from server (InternalError): error when creating "test-security-policy.yaml": Internal error occurred: failed calling webhook "msecuritypolicy.zelyo.ai": failed to call webhook: the server could not find the requested resource`

#### Root Cause
This typically happens when the path defined in the `MutatingWebhookConfiguration` or `ValidatingWebhookConfiguration` does not match the path the operator is listening on. 

In some versions of the Helm chart, the paths use the domain `zelyo-operator-com`, while the operator uses `zelyo-ai`.

#### Solution (Manual Patch)
Run these commands to align the configuration with the operator:

```bash
# Patch the Mutating Webhook
kubectl patch mutatingwebhookconfiguration zelyo-operator --type='json' \
  -p='[{"op": "replace", "path": "/webhooks/0/clientConfig/service/path", "value": "/mutate-zelyo-ai-v1alpha1-securitypolicy"}]'

# Patch the Validating Webhook
kubectl patch validatingwebhookconfiguration zelyo-operator --type='json' \
  -p='[{"op": "replace", "path": "/webhooks/0/clientConfig/service/path", "value": "/validate-zelyo-ai-v1alpha1-securitypolicy"}]'
```

After patching, retry your `kubectl apply` — it should work immediately.

> [!NOTE]
> **Permanent Fix in Progress**
> This path mismatch only affects the published OCI chart `v0.0.1`. The local Helm chart template has been updated with the correct paths and the fix will be included in the next release.

---

## Operator Pod Stuck in Pending

**Root Cause**: Not enough cluster resources (CPU/Memory).

**Fix**:
```bash
kubectl describe pod -n zelyo-system <pod-name>
```
Look for `Insufficient cpu` or `Insufficient memory` in the Events section. Increase your Docker resource limits or use a larger node.

---

## ImagePullBackOff

**Root Cause**: The operator image tag does not exist in the registry, or you forgot to import a local image into k3d.

**Fix for local image**:
```bash
k3d image import zelyo-operator:local -c zelyo
```

**Fix for OCI:** Ensure you're using a valid tag:
```bash
helm install zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator --version v0.0.1 ...
```

---

## kubectl Cannot Connect to Server

**Root Cause**: Your `kubectl` context is pointing at an old or deleted cluster.

**Fix**: Re-sync the kubeconfig from k3d:
```bash
k3d kubeconfig merge zelyo --kubeconfig-switch-context
```

Then verify:
```bash
kubectl get nodes
```

---

## Slack Notifications

### No Slack messages received
If you don't receive Slack messages despite having a `NotificationChannel`:

1.  **Check Operator Logs**: 
    ```bash
    kubectl logs -n zelyo-system deploy/zelyo-operator | grep -i "Successfully sent notifications"
    ```
    *If you see this log, the operator successfully contacted Slack.*

2.  **Verify Webhook URL**: 
    ```bash
    kubectl get secret slack-token -n zelyo-system -o jsonpath='{.data.webhook-url}' | base64 -d
    ```
    *Ensure the URL starts with `https://hooks.slack.com/services/...`*

3.  **Check Image Version**:
    If you see scans happening but no "Successfully sent" logs, you might be running an old version from GHCR.
    ```bash
    kubectl get deployment zelyo-operator -n zelyo-system -o jsonpath='{.spec.template.spec.containers[0].image}'
    ```
    *If it shows `0.0.1`, follow the **Build and Deploy the Local Operator** steps in the [End-to-End Guide](./end-to-end-guide.md).*

4.  **Check Channel Existence**:
    ```bash
    kubectl get notificationchannels -n zelyo-system
    ```

---

## AI Reasoning (LLM)

### Error: `API error 429` (Rate Limit)
If PRs are not being created, check the logs for LLM failures:
```bash
kubectl logs -n zelyo-system deploy/zelyo-operator | grep -i "LLM analysis failed"
```

**Root Cause**: Free-tier models (Nvidia/Nemotron) have strict per-day/per-minute usage limits.
**Fix**: Add $1 credit to OpenRouter and switch your `ZelyoConfig` to a paid model like `anthropic/claude-haiku`.

---

## GitOps & PRs

### PRs not being created in GitHub
1.  **Check Engine Initialization**:
    ```bash
    kubectl logs -n zelyo-system deploy/zelyo-operator | grep -i "Successfully initialized GitOps engine"
    ```
    *This confirms your GitHub PAT/Token and Repository URL are correctly wired.*

2.  **Verify PR Creation**:
    ```bash
    kubectl logs -n zelyo-system deploy/zelyo-operator | grep -i "Pull request created successfully"
    ```
