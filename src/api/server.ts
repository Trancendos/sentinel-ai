/**
 * Sentinel AI — REST API Server
 *
 * Exposes service health monitoring, SLA reporting, active polling,
 * incident tracking, and watchdog alerting endpoints for the
 * Trancendos mesh. Full 24-service coverage.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import {
  WatchdogEngine,
  ServiceStatus,
  CheckType,
  WatchdogAlertSeverity,
  ServiceTier,
} from '../watchdog/watchdog-engine';
import { logger } from '../utils/logger';


// ============================================================================
// IAM MIDDLEWARE — Trancendos 2060 Standard (TRN-PROD-001)
// ============================================================================
import { createHash, createHmac } from 'crypto';

const IAM_JWT_SECRET = process.env.IAM_JWT_SECRET || process.env.JWT_SECRET || '';
const IAM_ALGORITHM = process.env.JWT_ALGORITHM || 'HS512';
const SERVICE_ID = 'sentinel';
const MESH_ADDRESS = process.env.MESH_ADDRESS || 'sentinel.agent.local';

function sha512Audit(data: string): string {
  return createHash('sha512').update(data).digest('hex');
}

function b64urlDecode(s: string): string {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(b64 + '='.repeat((4 - b64.length % 4) % 4), 'base64').toString('utf8');
}

interface JWTClaims {
  sub: string; email?: string; role?: string;
  active_role_level?: number; permissions?: string[];
  exp?: number; jti?: string;
}

function verifyIAMToken(token: string): JWTClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, sig] = parts;
    const header = JSON.parse(b64urlDecode(h));
    const alg = header.alg === 'HS512' ? 'sha512' : 'sha256';
    const expected = createHmac(alg, IAM_JWT_SECRET)
      .update(`${h}.${p}`).digest('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    if (expected !== sig) return null;
    const claims = JSON.parse(b64urlDecode(p)) as JWTClaims;
    if (claims.exp && Date.now() / 1000 > claims.exp) return null;
    return claims;
  } catch { return null; }
}

function requireIAMLevel(maxLevel: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) { res.status(401).json({ error: 'Authentication required', service: SERVICE_ID }); return; }
    const claims = verifyIAMToken(token);
    if (!claims) { res.status(401).json({ error: 'Invalid or expired token', service: SERVICE_ID }); return; }
    const level = claims.active_role_level ?? 6;
    if (level > maxLevel) {
      console.log(JSON.stringify({ level: 'audit', decision: 'DENY', service: SERVICE_ID,
        principal: claims.sub, requiredLevel: maxLevel, actualLevel: level, path: req.path,
        integrityHash: sha512Audit(`DENY:${claims.sub}:${req.path}:${Date.now()}`),
        timestamp: new Date().toISOString() }));
      res.status(403).json({ error: 'Insufficient privilege level', required: maxLevel, actual: level });
      return;
    }
    (req as any).principal = claims;
    next();
  };
}

function iamRequestMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Service-Id', SERVICE_ID);
  res.setHeader('X-Mesh-Address', MESH_ADDRESS);
  res.setHeader('X-IAM-Version', '1.0');
  const traceId = req.headers['x-trace-id'] || `sentinel-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  res.setHeader('X-Trace-Id', traceId as string);
  (req as any).traceId = traceId;
  next();
}

function iamHealthStatus() {
  return {
    iam: {
      version: '1.0', algorithm: IAM_ALGORITHM,
      status: IAM_JWT_SECRET ? 'configured' : 'unconfigured',
      meshAddress: MESH_ADDRESS,
      routingProtocol: process.env.MESH_ROUTING_PROTOCOL || 'static_port',
      cryptoMigrationPath: 'hmac_sha512 → ml_kem (2030) → hybrid_pqc (2040) → slh_dsa (2060)',
    },
  };
}
// ============================================================================
// END IAM MIDDLEWARE
// ============================================================================

// ── Bootstrap ────────────────────────────────────────────────────────────────

const app = express();
export const watchdog = new WatchdogEngine();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(iamRequestMiddleware);
app.use(morgan('combined', {
  stream: { write: (msg: string) => logger.info(msg.trim()) },
}));

// ── Helpers ──────────────────────────────────────────────────────────────────

function ok(res: Response, data: unknown, status = 200): void {
  res.status(status).json({ success: true, data, timestamp: new Date().toISOString() });
}

function fail(res: Response, message: string, status = 400): void {
  res.status(status).json({ success: false, error: message, timestamp: new Date().toISOString() });
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1: HEALTH & METRICS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/health', (_req, res) => {
  const stats = watchdog.getStats();
  ok(res, {
    status: 'healthy',
    service: 'sentinel-ai',
    role: 'ecosystem-watchdog',
    uptime: process.uptime(),
    activePolling: stats.activePolling,
    watchdog: {
      totalServices: stats.totalServices,
      healthyServices: stats.healthyServices,
      degradedServices: stats.degradedServices,
      downServices: stats.downServices,
      overallUptime: stats.overallUptime,
      slaBreaches: stats.slaBreaches,
    },
    ...iamHealthStatus(),
    mesh: {
      address: MESH_ADDRESS,
      protocol: process.env.MESH_ROUTING_PROTOCOL || 'static_port',
    },
  });
});

app.get('/metrics', (_req, res) => {
  ok(res, {
    ...watchdog.getStats(),
    memory: process.memoryUsage(),
    uptime: process.uptime(),
  });
});

// Prometheus text format export
app.get('/metrics/prometheus', (_req, res) => {
  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(watchdog.exportPrometheusText());
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2: SERVICE MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

// GET /services — list all watched services
app.get('/services', (req, res) => {
  const { status, tier } = req.query;
  let services;
  if (tier) {
    services = watchdog.getServicesByTier(tier as ServiceTier);
  } else {
    services = watchdog.getServices(status as ServiceStatus | undefined);
  }
  ok(res, { services, count: services.length });
});

// GET /services/:id — get a specific service
app.get('/services/:id', (req, res) => {
  const service = watchdog.getService(req.params.id);
  if (!service) return fail(res, 'Service not found', 404);
  ok(res, service);
});

// POST /services — register a new service
app.post('/services', (req, res) => {
  const { name, url, port, tier, checkInterval, timeout } = req.body;
  if (!name || !url || !port) {
    return fail(res, 'name, url, port are required');
  }
  const service = watchdog.registerService({ name, url, port, tier, checkInterval, timeout });
  ok(res, service, 201);
});

// DELETE /services/:id — remove a service
app.delete('/services/:id', (req, res) => {
  const deleted = watchdog.removeService(req.params.id);
  if (!deleted) return fail(res, 'Service not found', 404);
  ok(res, { deleted: true, id: req.params.id });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3: HEALTH CHECKS
// ═══════════════════════════════════════════════════════════════════════════════

// POST /checks — record a health check result
app.post('/checks', (req, res) => {
  const { serviceId, type, status, latency, errorMessage, responseCode } = req.body;
  if (!serviceId || !type || !status) {
    return fail(res, 'serviceId, type, status are required');
  }
  try {
    const check = watchdog.recordCheck({
      serviceId,
      type: type as CheckType,
      status: status as ServiceStatus,
      latency,
      errorMessage,
      responseCode,
    });
    ok(res, check, 201);
  } catch (err: any) {
    fail(res, err.message, 404);
  }
});

// GET /checks — list recent checks
app.get('/checks', (req, res) => {
  const { serviceId, limit } = req.query;
  const checks = watchdog.getChecks(
    serviceId as string | undefined,
    limit ? Number(limit) : 100
  );
  ok(res, { checks, count: checks.length });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4: ACTIVE POLLING CONTROL
// ═══════════════════════════════════════════════════════════════════════════════

// POST /polling/start — start active health polling
app.post('/polling/start', (_req, res) => {
  watchdog.startPolling();
  ok(res, { message: 'Active health polling started', active: true });
});

// POST /polling/stop — stop active health polling
app.post('/polling/stop', (_req, res) => {
  watchdog.stopPolling();
  ok(res, { message: 'Active health polling stopped', active: false });
});

// GET /polling/status — get polling status
app.get('/polling/status', (_req, res) => {
  ok(res, { active: watchdog.isPollingActive() });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5: ALERTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /alerts — list alerts
app.get('/alerts', (req, res) => {
  const includeAcknowledged = req.query.includeAcknowledged === 'true';
  const alerts = watchdog.getAlerts(includeAcknowledged);
  ok(res, { alerts, count: alerts.length });
});

// POST /alerts — raise an alert manually
app.post('/alerts', (req, res) => {
  const { serviceId, severity, message, channel } = req.body;
  if (!serviceId || !severity || !message) {
    return fail(res, 'serviceId, severity, message are required');
  }
  const alert = watchdog.raiseAlert({
    serviceId,
    severity: severity as WatchdogAlertSeverity,
    message,
    channel,
  });
  ok(res, alert, 201);
});

// PATCH /alerts/:id/acknowledge — acknowledge an alert
app.patch('/alerts/:id/acknowledge', (req, res) => {
  const alert = watchdog.acknowledgeAlert(req.params.id);
  if (!alert) return fail(res, 'Alert not found', 404);
  ok(res, alert);
});

// PATCH /alerts/:id/resolve — resolve an alert
app.patch('/alerts/:id/resolve', (req, res) => {
  const alert = watchdog.resolveAlert(req.params.id);
  if (!alert) return fail(res, 'Alert not found', 404);
  ok(res, alert);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6: SLA REPORTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /sla — generate SLA report for all services
app.get('/sla', (req, res) => {
  const { serviceId } = req.query;
  const reports = watchdog.generateSLAReport(serviceId as string | undefined);
  const breaches = reports.filter(r => r.slaBreached);
  ok(res, {
    reports,
    summary: {
      totalServices: reports.length,
      slaMet: reports.filter(r => r.slaMet).length,
      slaBreached: breaches.length,
      overallUptime: reports.length > 0
        ? Math.round((reports.reduce((sum, r) => sum + r.uptimePercent, 0) / reports.length) * 1000) / 1000
        : 100,
    },
    breaches: breaches.map(b => ({
      service: b.serviceName,
      uptime: b.uptimePercent,
      target: b.slaTarget,
      gap: Math.round((b.slaTarget - b.uptimePercent) * 1000) / 1000,
    })),
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7: INCIDENTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /incidents — list recent incidents
app.get('/incidents', (req, res) => {
  const limit = req.query.limit ? Number(req.query.limit) : 50;
  const incidents = watchdog.getIncidents(limit);
  ok(res, { incidents, count: incidents.length });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 8: DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

// GET /dashboard — full watchdog dashboard payload
app.get('/dashboard', (_req, res) => {
  const stats = watchdog.getStats();
  const services = watchdog.getServices();
  const alerts = watchdog.getAlerts(false);
  const slaReports = watchdog.generateSLAReport();
  const incidents = watchdog.getIncidents(20);

  ok(res, {
    stats,
    services: services.map(s => ({
      name: s.name,
      tier: s.tier,
      status: s.status,
      uptime: Math.round(s.uptime * 1000) / 1000,
      avgLatency: Math.round(s.avgLatency * 100) / 100,
      p95Latency: Math.round(s.p95Latency * 100) / 100,
      consecutiveFailures: s.consecutiveFailures,
      lastChecked: s.lastChecked,
    })),
    recentAlerts: alerts.slice(0, 10),
    slaBreaches: slaReports.filter(r => r.slaBreached).map(r => ({
      service: r.serviceName,
      uptime: r.uptimePercent,
      target: r.slaTarget,
    })),
    recentIncidents: incidents.slice(0, 10),
    timestamp: new Date().toISOString(),
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 9: STATS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/stats', (_req, res) => {
  ok(res, watchdog.getStats());
});

// ── Error Handler ────────────────────────────────────────────────────────────

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error({ err }, 'Unhandled error');
  fail(res, err.message || 'Internal server error', 500);
});

export { app };