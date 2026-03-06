/**
 * Sentinel AI — REST API Server
 *
 * Exposes service health monitoring, SLA reporting, and watchdog
 * alerting endpoints for the Trancendos mesh.
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

// ── Bootstrap ──────────────────────────────────────────────────────────────

const app = express();
export const watchdog = new WatchdogEngine();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined', {
  stream: { write: (msg: string) => logger.info(msg.trim()) },
}));

// ── Helpers ────────────────────────────────────────────────────────────────

function ok(res: Response, data: unknown, status = 200): void {
  res.status(status).json({ success: true, data, timestamp: new Date().toISOString() });
}

function fail(res: Response, message: string, status = 400): void {
  res.status(status).json({ success: false, error: message, timestamp: new Date().toISOString() });
}

function wrap(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => fn(req, res).catch(next);
}

// ── Health ─────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  const stats = watchdog.getStats();
  ok(res, {
    status: 'healthy',
    service: 'sentinel-ai',
    uptime: process.uptime(),
    meshHealth: {
      totalServices: stats.totalServices,
      healthyServices: stats.healthyServices,
      degradedServices: stats.degradedServices,
      downServices: stats.downServices,
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

// ── Services ───────────────────────────────────────────────────────────────

// GET /services — list all watched services
app.get('/services', (req, res) => {
  const { status } = req.query;
  const services = watchdog.getServices(status as ServiceStatus | undefined);
  ok(res, { services, count: services.length });
});

// GET /services/:id — get a specific service
app.get('/services/:id', (req, res) => {
  const service = watchdog.getService(req.params.id);
  if (!service) return fail(res, 'Service not found', 404);
  ok(res, service);
});

// POST /services — register a service for monitoring
app.post('/services', (req, res) => {
  const { name, endpoint, slaTarget, checkInterval, tags } = req.body;
  if (!name || !endpoint) return fail(res, 'name, endpoint are required');
  try {
    const service = watchdog.registerService({
      name,
      endpoint,
      slaTarget: slaTarget ? Number(slaTarget) : undefined,
      checkInterval: checkInterval ? Number(checkInterval) : undefined,
      tags,
    });
    ok(res, service, 201);
  } catch (err) {
    fail(res, (err as Error).message);
  }
});

// DELETE /services/:id — remove a service
app.delete('/services/:id', (req, res) => {
  const deleted = watchdog.removeService(req.params.id);
  if (!deleted) return fail(res, 'Service not found', 404);
  ok(res, { deleted: true, id: req.params.id });
});

// ── Health Checks ──────────────────────────────────────────────────────────

// GET /checks — list recent checks
app.get('/checks', (req, res) => {
  const { serviceId, limit } = req.query;
  const checks = watchdog.getChecks(
    serviceId as string | undefined,
    limit ? Number(limit) : 100,
  );
  ok(res, { checks, count: checks.length });
});

// POST /checks — record a health check result
app.post('/checks', (req, res) => {
  const { serviceId, type, success, latencyMs, message, metadata } = req.body;
  if (!serviceId || !type || success === undefined) {
    return fail(res, 'serviceId, type, success are required');
  }
  const validTypes: CheckType[] = ['health', 'latency', 'error_rate', 'uptime', 'custom'];
  if (!validTypes.includes(type)) {
    return fail(res, `type must be one of: ${validTypes.join(', ')}`);
  }
  try {
    const check = watchdog.recordCheck({
      serviceId,
      type: type as CheckType,
      success: Boolean(success),
      latencyMs: latencyMs ? Number(latencyMs) : undefined,
      message,
      metadata,
    });
    ok(res, check, 201);
  } catch (err) {
    fail(res, (err as Error).message);
  }
});

// ── Alerts ─────────────────────────────────────────────────────────────────

// GET /alerts — list watchdog alerts
app.get('/alerts', (req, res) => {
  const includeAcknowledged = req.query.includeAcknowledged === 'true';
  const alerts = watchdog.getAlerts(includeAcknowledged);
  ok(res, { alerts, count: alerts.length });
});

// POST /alerts — raise a watchdog alert
app.post('/alerts', (req, res) => {
  const { serviceId, severity, message, checkType } = req.body;
  if (!serviceId || !severity || !message) {
    return fail(res, 'serviceId, severity, message are required');
  }
  const validSeverities: WatchdogAlertSeverity[] = ['info', 'warning', 'critical'];
  if (!validSeverities.includes(severity)) {
    return fail(res, `severity must be one of: ${validSeverities.join(', ')}`);
  }
  try {
    const alert = watchdog.raiseAlert({
      serviceId,
      severity: severity as WatchdogAlertSeverity,
      message,
      checkType,
    });
    ok(res, alert, 201);
  } catch (err) {
    fail(res, (err as Error).message);
  }
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

// ── SLA Reports ────────────────────────────────────────────────────────────

// GET /sla — generate SLA report (all services or specific)
app.get('/sla', (req, res) => {
  const { serviceId } = req.query;
  const reports = watchdog.generateSLAReport(serviceId as string | undefined);
  ok(res, { reports, count: reports.length });
});

// ── Stats ──────────────────────────────────────────────────────────────────

app.get('/stats', (_req, res) => {
  ok(res, watchdog.getStats());
});

// ── Error Handler ──────────────────────────────────────────────────────────

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error({ err }, 'Unhandled error');
  fail(res, err.message || 'Internal server error', 500);
});

export { app };