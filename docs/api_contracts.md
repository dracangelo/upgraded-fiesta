# External Integration Contracts & Client SDK Guide

This document defines the API contracts, version-support policy, authentication protocols, and client integration workflows for the Enumscan platform.

## 1. API Version-Support Policy

- **Current Stable Version**: `v1` (endpoints prefixed with `/api/v1/`).
- **Semantic Versioning**: All public endpoints strictly adhere to Semantic Versioning 2.0.0.
  - Patch and minor releases never remove fields or alter required parameters.
  - Additive changes (new endpoints, new response fields, optional query parameters) may occur within `v1`.
- **Deprecation Policy**:
  - Any endpoint planned for retirement will be marked `deprecated: true` in the OpenAPI specification at least 6 months prior to removal.
  - HTTP response headers will include `Sunset: <date>` and `Link: <url>; rel="deprecation"`.

---

## 2. Authentication & Authorization Protocols

| Scheme | Header / Transport | Usage |
| --- | --- | --- |
| **API Token** | `Authorization: Bearer <token>` | Automation scripts, CI/CD pipelines, and reporting |
| **Session Token** | `Authorization: Bearer sess_<token>` | Interactive web dashboard and user sessions |
| **Distributed HMAC** | `X-Agent-ID`, `X-Timestamp`, `X-Nonce`, `X-Signature` | Distributed agent heartbeat and evidence uploads |
| **Multi-Tenancy** | `X-Tenant-ID: <org-id>` | Cross-organization isolation and scoping |

---

## 3. Supported Client Integration Workflows

### Python Client (`requests`)

```python
import requests

class EnumscanClient:
    def __init__(self, base_url="http://127.0.0.1:8080", token=None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def check_health(self):
        resp = self.session.get(f"{self.base_url}/api/v1/health")
        resp.raise_for_status()
        return resp.json()

    def generate_plan(self, target, authorization, profile="standard"):
        payload = {
            "target": target,
            "authorization": authorization,
            "profile": profile
        }
        resp = self.session.post(f"{self.base_url}/api/v1/engagement/plan", json=payload)
        resp.raise_for_status()
        return resp.json()

    def list_findings(self, scan_id):
        resp = self.session.get(f"{self.base_url}/api/v1/findings", params={"scan_id": scan_id})
        resp.raise_for_status()
        return resp.json()
```

### Go Client Workflow

```go
package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
)

type Client struct {
    baseURL    string
    httpClient *http.Client
    token      string
}

func NewClient(baseURL, token string) *Client {
    return &Client{
        baseURL:    baseURL,
        token:      token,
        httpClient: &http.Client{},
    }
}

func (c *Client) Health(ctx context.Context) error {
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/health", nil)
    if c.token != "" {
        req.Header.Set("Authorization", "Bearer "+c.token)
    }
    resp, err := c.httpClient.Do(req)
    if err != nil || resp.StatusCode != http.StatusOK {
        return fmt.Errorf("health check failed")
    }
    defer resp.Body.Close()
    return nil
}
```

### cURL Quickstart

```bash
# 1. Health check
curl -s http://127.0.0.1:8080/api/v1/health

# 2. Generate engagement plan
curl -s -X POST http://127.0.0.1:8080/api/v1/engagement/plan \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.0/24","authorization":"AUTH-2026-VAL"}'

# 3. Fetch Prometheus metrics
curl -s http://127.0.0.1:8080/api/v1/metrics
```
