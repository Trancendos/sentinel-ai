# Sentinel AI 🛡️

> Service health monitoring, SLA tracking, and watchdog alerting for the Trancendos mesh.
> Zero-cost compliant — no LLM calls, all rule-based health evaluation.

**Port:** `3021`
**Architecture:** Trancendos Industry 6.0 / 2060 Standard

---

## Overview

Sentinel AI is the mesh-wide watchdog service. It monitors the health of all registered services, tracks SLA compliance, records health check results, and raises alerts when services degrade or go down. It uses consecutive failure tracking to determine service status transitions.

---

## Status Logic

| Condition | Status |
|-----------|--------|
| 3+ consecutive failures | `down` |
| 1–2 consecutive failures | `degraded` |
| Last check successful | `healthy` |
| No checks recorded | `unknown` |

---

## SLA Tracking

- Default SLA target: **99.9% uptime**
- Per-service configurable SLA targets
- SLA reports include: uptime%, total checks, passed checks, SLA breach flag

---

## API Reference

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service health + mesh health summary |
| GET | `/metrics` | Runtime metrics + watchdog stats |

### Services

| Method | Path | Description |
|--------|------|-------------|
| GET | `/services` | List services (filter by status) |
| GET | `/services/:id` | Get a specific service |
| POST | `/services` | Register a service for monitoring |
| DELETE | `/services/:id` | Remove a service |

### Health Checks

| Method | Path | Description |
|--------|------|-------------|
| GET | `/checks` | List recent checks (filter by serviceId, limit) |
| POST | `/checks` | Record a health check result |

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/alerts` | List alerts (include acknowledged with `?includeAcknowledged=true`) |
| POST | `/alerts` | Raise a watchdog alert |
| PATCH | `/alerts/:id/acknowledge` | Acknowledge an alert |
| PATCH | `/alerts/:id/resolve` | Resolve an alert |

### SLA Reports

| Method | Path | Description |
|--------|------|-------------|
| GET | `/sla` | Generate SLA report (all or specific service) |

### Stats

| Method | Path | Description |
|--------|------|-------------|
| GET | `/stats` | Watchdog statistics |

---

## Usage Examples

### Register a Service

```bash
curl -X POST http://localhost:3021/services \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-service",
    "endpoint": "http://my-service:3000/health",
    "slaTarget": 99.9,
    "tags": ["api", "critical"]
  }'
```

### Record a Health Check

```bash
curl -X POST http://localhost:3021/checks \
  -H "Content-Type: application/json" \
  -d '{
    "serviceId": "<service-id>",
    "type": "health",
    "success": true,
    "latencyMs": 42
  }'
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3021` | HTTP server port |
| `HOST` | `0.0.0.0` | HTTP server host |
| `LOG_LEVEL` | `info` | Pino log level |
| `SLA_INTERVAL_MS` | `1800000` | Periodic SLA summary interval (ms) |

---

## Development

```bash
npm install
npm run dev       # tsx watch mode
npm run build     # compile TypeScript
npm start         # run compiled output
```

---

## Default Monitored Services

Sentinel AI seeds 7 default mesh services on startup:
- cornelius-ai, norman-ai, the-dr-ai, guardian-ai, dorris-ai, prometheus-ai, the-observatory

---

*Part of the Trancendos Industry 6.0 mesh — 2060 Standard*