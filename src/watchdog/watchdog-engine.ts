/**
 * Sentinel AI — Watchdog & Alert Engine
 *
 * Continuous watchdog monitoring for the Trancendos mesh.
 * Monitors service health, uptime, SLA compliance, and triggers
 * alerts when thresholds are breached.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

// ── Types ─────────────────────────────────────────────────────────────────

export type ServiceStatus = 'healthy' | 'degraded' | 'down' | 'unknown';
export type AlertChannel = 'internal' | 'mesh' | 'log';
export type WatchdogAlertSeverity = 'info' | 'warning' | 'critical';
export type CheckType = 'health' | 'latency' | 'error_rate' | 'uptime' | 'custom';

export interface WatchedService {
  id: string;
  name: string;
  url: string;
  port: number;
  checkInterval: number;   // ms
  timeout: number;         // ms
  status: ServiceStatus;
  uptime: number;          // percentage 0-100
  lastChecked?: Date;
  lastStatusChange?: Date;
  consecutiveFailures: number;
  totalChecks: number;
  successfulChecks: number;
  avgLatency: number;      // ms
  createdAt: Date;
}

export interface WatchdogCheck {
  id: string;
  serviceId: string;
  type: CheckType;
  status: ServiceStatus;
  latency?: number;
  errorMessage?: string;
  timestamp: Date;
}

export interface WatchdogAlert {
  id: string;
  serviceId: string;
  serviceName: string;
  severity: WatchdogAlertSeverity;
  message: string;
  channel: AlertChannel;
  acknowledged: boolean;
  acknowledgedAt?: Date;
  resolvedAt?: Date;
  createdAt: Date;
}

export interface SLAReport {
  serviceId: string;
  serviceName: string;
  period: string;
  uptimePercent: number;
  slaTarget: number;
  slaMet: boolean;
  totalChecks: number;
  successfulChecks: number;
  avgLatency: number;
  incidents: number;
}

export interface WatchdogStats {
  totalServices: number;
  healthyServices: number;
  degradedServices: number;
  downServices: number;
  totalAlerts: number;
  unacknowledgedAlerts: number;
  criticalAlerts: number;
  overallUptime: number;
}

// ── Watchdog Engine ───────────────────────────────────────────────────────

export class WatchdogEngine {
  private services: Map<string, WatchedService> = new Map();
  private checks: WatchdogCheck[] = [];
  private alerts: Map<string, WatchdogAlert> = new Map();
  private readonly SLA_TARGET = 99.9;

  constructor() {
    this.seedDefaultServices();
    logger.info('WatchdogEngine (Sentinel AI) initialized — watching the mesh');
  }

  // ── Service Management ──────────────────────────────────────────────────

  registerService(params: {
    name: string;
    url: string;
    port: number;
    checkInterval?: number;
    timeout?: number;
  }): WatchedService {
    const service: WatchedService = {
      id: uuidv4(),
      name: params.name,
      url: params.url,
      port: params.port,
      checkInterval: params.checkInterval || 30000,
      timeout: params.timeout || 5000,
      status: 'unknown',
      uptime: 100,
      consecutiveFailures: 0,
      totalChecks: 0,
      successfulChecks: 0,
      avgLatency: 0,
      createdAt: new Date(),
    };
    this.services.set(service.id, service);
    logger.info({ serviceId: service.id, name: service.name, port: service.port }, 'Service registered for watchdog');
    return service;
  }

  getService(serviceId: string): WatchedService | undefined {
    return this.services.get(serviceId);
  }

  getServices(status?: ServiceStatus): WatchedService[] {
    let services = Array.from(this.services.values());
    if (status) services = services.filter(s => s.status === status);
    return services.sort((a, b) => a.name.localeCompare(b.name));
  }

  removeService(serviceId: string): boolean {
    return this.services.delete(serviceId);
  }

  // ── Health Checks ───────────────────────────────────────────────────────

  recordCheck(params: {
    serviceId: string;
    type: CheckType;
    status: ServiceStatus;
    latency?: number;
    errorMessage?: string;
  }): WatchdogCheck {
    const service = this.services.get(params.serviceId);
    if (!service) throw new Error(`Service ${params.serviceId} not found`);

    const check: WatchdogCheck = {
      id: uuidv4(),
      serviceId: params.serviceId,
      type: params.type,
      status: params.status,
      latency: params.latency,
      errorMessage: params.errorMessage,
      timestamp: new Date(),
    };

    this.checks.push(check);
    if (this.checks.length > 10000) this.checks.shift();

    // Update service stats
    const prevStatus = service.status;
    service.totalChecks++;
    service.lastChecked = new Date();

    if (params.status === 'healthy') {
      service.successfulChecks++;
      service.consecutiveFailures = 0;
      if (params.latency !== undefined) {
        service.avgLatency = service.avgLatency === 0
          ? params.latency
          : (service.avgLatency * 0.9 + params.latency * 0.1);
      }
    } else {
      service.consecutiveFailures++;
    }

    service.uptime = service.totalChecks > 0
      ? (service.successfulChecks / service.totalChecks) * 100
      : 100;

    // Update status
    if (service.consecutiveFailures >= 3) {
      service.status = 'down';
    } else if (service.consecutiveFailures >= 1) {
      service.status = 'degraded';
    } else {
      service.status = params.status;
    }

    if (service.status !== prevStatus) {
      service.lastStatusChange = new Date();
      this.handleStatusChange(service, prevStatus);
    }

    return check;
  }

  getChecks(serviceId?: string, limit = 100): WatchdogCheck[] {
    let checks = [...this.checks];
    if (serviceId) checks = checks.filter(c => c.serviceId === serviceId);
    return checks.slice(-limit).reverse();
  }

  // ── Alerts ──────────────────────────────────────────────────────────────

  raiseAlert(params: {
    serviceId: string;
    severity: WatchdogAlertSeverity;
    message: string;
    channel?: AlertChannel;
  }): WatchdogAlert {
    const service = this.services.get(params.serviceId);
    const alert: WatchdogAlert = {
      id: uuidv4(),
      serviceId: params.serviceId,
      serviceName: service?.name || 'unknown',
      severity: params.severity,
      message: params.message,
      channel: params.channel || 'internal',
      acknowledged: false,
      createdAt: new Date(),
    };
    this.alerts.set(alert.id, alert);
    logger.warn({ alertId: alert.id, severity: alert.severity, service: alert.serviceName }, alert.message);
    return alert;
  }

  acknowledgeAlert(alertId: string): WatchdogAlert | undefined {
    const alert = this.alerts.get(alertId);
    if (!alert) return undefined;
    alert.acknowledged = true;
    alert.acknowledgedAt = new Date();
    return alert;
  }

  resolveAlert(alertId: string): WatchdogAlert | undefined {
    const alert = this.alerts.get(alertId);
    if (!alert) return undefined;
    alert.resolvedAt = new Date();
    if (!alert.acknowledged) {
      alert.acknowledged = true;
      alert.acknowledgedAt = new Date();
    }
    return alert;
  }

  getAlerts(includeAcknowledged = false): WatchdogAlert[] {
    let alerts = Array.from(this.alerts.values());
    if (!includeAcknowledged) alerts = alerts.filter(a => !a.acknowledged);
    return alerts.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  // ── SLA Reports ──────────────────────────────────────────────────────────

  generateSLAReport(serviceId?: string): SLAReport[] {
    const services = serviceId
      ? [this.services.get(serviceId)].filter(Boolean) as WatchedService[]
      : Array.from(this.services.values());

    return services.map(service => {
      const incidents = Array.from(this.alerts.values())
        .filter(a => a.serviceId === service.id && a.severity === 'critical').length;

      return {
        serviceId: service.id,
        serviceName: service.name,
        period: '24h',
        uptimePercent: service.uptime,
        slaTarget: this.SLA_TARGET,
        slaMet: service.uptime >= this.SLA_TARGET,
        totalChecks: service.totalChecks,
        successfulChecks: service.successfulChecks,
        avgLatency: service.avgLatency,
        incidents,
      };
    });
  }

  // ── Stats ────────────────────────────────────────────────────────────────

  getStats(): WatchdogStats {
    const services = Array.from(this.services.values());
    const alerts = Array.from(this.alerts.values());
    const totalUptime = services.length > 0
      ? services.reduce((sum, s) => sum + s.uptime, 0) / services.length
      : 100;

    return {
      totalServices: services.length,
      healthyServices: services.filter(s => s.status === 'healthy').length,
      degradedServices: services.filter(s => s.status === 'degraded').length,
      downServices: services.filter(s => s.status === 'down').length,
      totalAlerts: alerts.length,
      unacknowledgedAlerts: alerts.filter(a => !a.acknowledged).length,
      criticalAlerts: alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length,
      overallUptime: totalUptime,
    };
  }

  // ── Private ──────────────────────────────────────────────────────────────

  private handleStatusChange(service: WatchedService, prevStatus: ServiceStatus): void {
    if (service.status === 'down') {
      this.raiseAlert({
        serviceId: service.id,
        severity: 'critical',
        message: `Service ${service.name} is DOWN (was: ${prevStatus})`,
        channel: 'mesh',
      });
    } else if (service.status === 'degraded') {
      this.raiseAlert({
        serviceId: service.id,
        severity: 'warning',
        message: `Service ${service.name} is DEGRADED (${service.consecutiveFailures} consecutive failures)`,
      });
    } else if (service.status === 'healthy' && prevStatus !== 'unknown') {
      this.raiseAlert({
        serviceId: service.id,
        severity: 'info',
        message: `Service ${service.name} recovered to HEALTHY (was: ${prevStatus})`,
      });
    }
  }

  private seedDefaultServices(): void {
    const defaults = [
      { name: 'cornelius-ai', url: 'http://cornelius-ai', port: 3000 },
      { name: 'the-dr-ai', url: 'http://the-dr-ai', port: 3001 },
      { name: 'norman-ai', url: 'http://norman-ai', port: 3002 },
      { name: 'guardian-ai', url: 'http://guardian-ai', port: 3004 },
      { name: 'dorris-ai', url: 'http://dorris-ai', port: 3005 },
      { name: 'the-hive', url: 'http://the-hive', port: 3010 },
      { name: 'the-observatory', url: 'http://the-observatory', port: 3012 },
    ];
    for (const d of defaults) this.registerService(d);
    logger.info({ count: defaults.length }, 'Default mesh services registered for watchdog');
  }
}