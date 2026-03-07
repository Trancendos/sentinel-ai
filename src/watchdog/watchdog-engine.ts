/**
 * Sentinel AI — Watchdog & Alert Engine
 *
 * Continuous watchdog monitoring for ALL 24+ Trancendos mesh services.
 * Monitors service health, uptime, SLA compliance, latency tracking,
 * and triggers alerts when thresholds are breached.
 * Includes active health polling and Prometheus-AI integration.
 *
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

// ── Types ─────────────────────────────────────────────────────────────

export type ServiceStatus = 'healthy' | 'degraded' | 'down' | 'unknown';
export type AlertChannel = 'internal' | 'mesh' | 'log' | 'prometheus';
export type WatchdogAlertSeverity = 'info' | 'warning' | 'critical';
export type CheckType = 'health' | 'latency' | 'error_rate' | 'uptime' | 'custom';
export type ServiceTier = 'core' | 'agent' | 'platform' | 'infrastructure' | 'marketplace';

export interface WatchedService {
  id: string;
  name: string;
  tier: ServiceTier;
  url: string;
  port: number;
  healthEndpoint: string;
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
  p95Latency: number;      // ms
  p99Latency: number;      // ms
  latencyHistory: number[];// last 100 latency values
  createdAt: Date;
}

export interface WatchdogCheck {
  id: string;
  serviceId: string;
  type: CheckType;
  status: ServiceStatus;
  latency?: number;
  errorMessage?: string;
  responseCode?: number;
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
  tier: ServiceTier;
  period: string;
  uptimePercent: number;
  slaTarget: number;
  slaBreached: boolean;
  slaMet: boolean;
  totalChecks: number;
  successfulChecks: number;
  avgLatency: number;
  p95Latency: number;
  p99Latency: number;
  incidents: number;
  lastChecked?: Date;
}

export interface WatchdogStats {
  totalServices: number;
  healthyServices: number;
  degradedServices: number;
  downServices: number;
  unknownServices: number;
  totalAlerts: number;
  openAlerts: number;
  unacknowledgedAlerts: number;
  criticalAlerts: number;
  overallUptime: number;
  slaBreaches: number;
  activePolling: boolean;
}

export interface IncidentRecord {
  id: string;
  serviceId: string;
  serviceName: string;
  severity: WatchdogAlertSeverity;
  startedAt: Date;
  resolvedAt?: Date;
  duration?: number; // ms
  description: string;
  rootCause?: string;
}

// ── Full Ecosystem Service Registry ───────────────────────────────────

const ECOSYSTEM_SERVICES: Array<{
  name: string; tier: ServiceTier; port: number;
}> = [
  // Wave 1 — Core
  { name: 'infinity-portal',   tier: 'core',           port: 3099 },
  // Wave 2 — Agents
  { name: 'cornelius-ai',      tier: 'agent',          port: 3000 },
  { name: 'the-dr-ai',         tier: 'agent',          port: 3001 },
  { name: 'norman-ai',         tier: 'agent',          port: 3002 },
  { name: 'guardian-ai',       tier: 'agent',          port: 3004 },
  { name: 'dorris-ai',         tier: 'agent',          port: 3005 },
  // Wave 3 — Platform
  { name: 'the-agora',         tier: 'platform',       port: 3010 },
  { name: 'the-citadel',       tier: 'platform',       port: 3011 },
  { name: 'the-hive',          tier: 'platform',       port: 3012 },
  { name: 'the-library',       tier: 'platform',       port: 3013 },
  { name: 'the-nexus',         tier: 'platform',       port: 3014 },
  { name: 'the-observatory',   tier: 'platform',       port: 3015 },
  { name: 'the-treasury',      tier: 'platform',       port: 3016 },
  { name: 'the-workshop',      tier: 'platform',       port: 3017 },
  { name: 'arcadia',           tier: 'platform',       port: 3018 },
  // Wave 4 — Agents (extended) + Infrastructure
  { name: 'prometheus-ai',     tier: 'infrastructure', port: 3019 },
  { name: 'serenity-ai',       tier: 'agent',          port: 3020 },
  { name: 'sentinel-ai',       tier: 'infrastructure', port: 3021 },
  { name: 'oracle-ai',         tier: 'agent',          port: 3022 },
  { name: 'porter-family-ai',  tier: 'agent',          port: 3023 },
  { name: 'queen-ai',          tier: 'agent',          port: 3025 },
  { name: 'renik-ai',          tier: 'agent',          port: 3026 },
  { name: 'solarscene-ai',     tier: 'agent',          port: 3028 },
  // Wave 5 — Marketplace
  { name: 'api-marketplace',   tier: 'marketplace',    port: 3040 },
  { name: 'artifactory',       tier: 'marketplace',    port: 3041 },
  // Wave 6: The Studios
  { name: 'section7', port: 3050, wave: 6, critical: false },
  { name: 'style-and-shoot', port: 3051, wave: 6, critical: false },
  { name: 'fabulousa', port: 3052, wave: 6, critical: false },
  { name: 'tranceflow', port: 3053, wave: 6, critical: false },
  { name: 'tateking', port: 3054, wave: 6, critical: false },
  { name: 'the-digitalgrid', port: 3055, wave: 6, critical: false },
];

// ── Watchdog Engine ───────────────────────────────────────────────────

export class WatchdogEngine {
  private services: Map<string, WatchedService> = new Map();
  private checks: WatchdogCheck[] = [];
  private alerts: Map<string, WatchdogAlert> = new Map();
  private incidents: IncidentRecord[] = [];
  private readonly SLA_TARGET = 99.9;
  private pollingTimer: NodeJS.Timeout | null = null;
  private pollingActive = false;
  private readonly POLL_INTERVAL = Number(process.env.POLL_INTERVAL_MS ?? 30_000);
  private readonly POLL_TIMEOUT = Number(process.env.POLL_TIMEOUT_MS ?? 5_000);
  private prometheusUrl: string;

  constructor() {
    this.prometheusUrl = process.env.PROMETHEUS_URL || 'http://prometheus-ai:3019';
    this.seedAllServices();
    logger.info({ services: ECOSYSTEM_SERVICES.length }, 'WatchdogEngine (Sentinel AI) initialized — full ecosystem coverage');
  }

  // ── Service Management ──────────────────────────────────────────────

  private seedAllServices(): void {
    for (const svc of ECOSYSTEM_SERVICES) {
      const service: WatchedService = {
        id: svc.name,
        name: svc.name,
        tier: svc.tier,
        url: `http://${svc.name}`,
        port: svc.port,
        healthEndpoint: `/health`,
        checkInterval: this.POLL_INTERVAL,
        timeout: this.POLL_TIMEOUT,
        status: 'unknown',
        uptime: 100,
        consecutiveFailures: 0,
        totalChecks: 0,
        successfulChecks: 0,
        avgLatency: 0,
        p95Latency: 0,
        p99Latency: 0,
        latencyHistory: [],
        createdAt: new Date(),
      };
      this.services.set(svc.name, service);
    }
    logger.info({ count: ECOSYSTEM_SERVICES.length }, 'All ecosystem services registered for watchdog');
  }

  registerService(params: {
    name: string;
    url: string;
    port: number;
    tier?: ServiceTier;
    checkInterval?: number;
    timeout?: number;
  }): WatchedService {
    const service: WatchedService = {
      id: params.name,
      name: params.name,
      tier: params.tier || 'platform',
      url: params.url,
      port: params.port,
      healthEndpoint: '/health',
      checkInterval: params.checkInterval || this.POLL_INTERVAL,
      timeout: params.timeout || this.POLL_TIMEOUT,
      status: 'unknown',
      uptime: 100,
      consecutiveFailures: 0,
      totalChecks: 0,
      successfulChecks: 0,
      avgLatency: 0,
      p95Latency: 0,
      p99Latency: 0,
      latencyHistory: [],
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

  getServicesByTier(tier: ServiceTier): WatchedService[] {
    return Array.from(this.services.values())
      .filter(s => s.tier === tier)
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  removeService(serviceId: string): boolean {
    return this.services.delete(serviceId);
  }

  // ── Health Checks ───────────────────────────────────────────────────

  recordCheck(params: {
    serviceId: string;
    type: CheckType;
    status: ServiceStatus;
    latency?: number;
    errorMessage?: string;
    responseCode?: number;
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
      responseCode: params.responseCode,
      timestamp: new Date(),
    };

    this.checks.push(check);
    if (this.checks.length > 50000) this.checks = this.checks.slice(-25000);

    // Update service stats
    const prevStatus = service.status;
    service.totalChecks++;
    service.lastChecked = new Date();

    if (params.status === 'healthy') {
      service.successfulChecks++;
      service.consecutiveFailures = 0;
      if (params.latency !== undefined) {
        service.latencyHistory.push(params.latency);
        if (service.latencyHistory.length > 100) service.latencyHistory.shift();
        service.avgLatency = service.latencyHistory.reduce((a, b) => a + b, 0) / service.latencyHistory.length;
        // Calculate percentiles
        const sorted = [...service.latencyHistory].sort((a, b) => a - b);
        service.p95Latency = sorted[Math.floor(sorted.length * 0.95)] || 0;
        service.p99Latency = sorted[Math.floor(sorted.length * 0.99)] || 0;
      }
    } else {
      service.consecutiveFailures++;
    }

    service.uptime = service.totalChecks > 0
      ? (service.successfulChecks / service.totalChecks) * 100
      : 100;

    // Update status with hysteresis
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

  // ── Active Health Polling ───────────────────────────────────────────

  startPolling(): void {
    if (this.pollingActive) {
      logger.warn('Polling already active');
      return;
    }
    this.pollingActive = true;
    logger.info({ interval: this.POLL_INTERVAL, services: this.services.size }, 'Starting active health polling');

    this.pollingTimer = setInterval(async () => {
      await this.pollAllServices();
    }, this.POLL_INTERVAL);

    // Initial poll
    this.pollAllServices().catch(err => {
      logger.error({ err }, 'Initial poll failed');
    });
  }

  stopPolling(): void {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
    this.pollingActive = false;
    logger.info('Active health polling stopped');
  }

  isPollingActive(): boolean {
    return this.pollingActive;
  }

  private async pollAllServices(): Promise<void> {
    const services = Array.from(this.services.values());
    const results = await Promise.allSettled(
      services.map(svc => this.pollService(svc))
    );

    let healthy = 0;
    let degraded = 0;
    let down = 0;

    for (const result of results) {
      if (result.status === 'fulfilled') {
        if (result.value === 'healthy') healthy++;
        else if (result.value === 'degraded') degraded++;
        else down++;
      } else {
        down++;
      }
    }

    logger.info(
      { total: services.length, healthy, degraded, down },
      '🛡️  Health poll cycle complete'
    );

    // Push aggregated snapshot to Prometheus-AI
    this.pushToPrometheus().catch(err => {
      logger.debug({ err: err.message }, 'Prometheus push skipped (service may be unavailable)');
    });
  }

  private async pollService(service: WatchedService): Promise<ServiceStatus> {
    const url = `${service.url}:${service.port}${service.healthEndpoint}`;
    const start = Date.now();

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), service.timeout);

      const response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'X-Sentinel-Check': 'true',
          'X-Trace-Id': `sentinel-poll-${Date.now()}`,
        },
      });

      clearTimeout(timeout);
      const latency = Date.now() - start;

      const status: ServiceStatus = response.ok ? 'healthy' : 'degraded';
      this.recordCheck({
        serviceId: service.id,
        type: 'health',
        status,
        latency,
        responseCode: response.status,
      });

      return status;
    } catch (err: any) {
      const latency = Date.now() - start;
      this.recordCheck({
        serviceId: service.id,
        type: 'health',
        status: 'down',
        latency,
        errorMessage: err.message || 'Connection failed',
      });
      return 'down';
    }
  }

  private async pushToPrometheus(): Promise<void> {
    const services = Array.from(this.services.values());
    const payload = {
      serviceId: 'sentinel-ai',
      metrics: services.map(svc => ({
        name: `sentinel_service_status_${svc.name.replace(/-/g, '_')}`,
        type: 'gauge' as const,
        value: svc.status === 'healthy' ? 1 : svc.status === 'degraded' ? 0.5 : 0,
        labels: { service: svc.name, tier: svc.tier },
      })),
    };

    try {
      await fetch(`${this.prometheusUrl}/ecosystem/ingest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    } catch {
      // Silently fail — prometheus may not be running yet
    }
  }

  // ── Alerts ──────────────────────────────────────────────────────────

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

    // Forward critical alerts to Prometheus-AI
    if (params.severity === 'critical') {
      this.forwardAlertToPrometheus(alert).catch(() => {});
    }

    return alert;
  }

  private async forwardAlertToPrometheus(alert: WatchdogAlert): Promise<void> {
    try {
      await fetch(`${this.prometheusUrl}/alerts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'sentinel_watchdog',
          severity: alert.severity,
          source: `sentinel:${alert.serviceId}`,
          message: alert.message,
        }),
      });
    } catch {
      // Silently fail
    }
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

  // ── SLA Reports ─────────────────────────────────────────────────────

  generateSLAReport(serviceId?: string): SLAReport[] {
    const services = serviceId
      ? [this.services.get(serviceId)].filter(Boolean) as WatchedService[]
      : Array.from(this.services.values());

    return services.map(service => {
      const incidents = Array.from(this.alerts.values())
        .filter(a => a.serviceId === service.id && a.severity === 'critical').length;

      const slaBreached = service.uptime < this.SLA_TARGET;

      return {
        serviceId: service.id,
        serviceName: service.name,
        tier: service.tier,
        period: '24h',
        uptimePercent: Math.round(service.uptime * 1000) / 1000,
        slaTarget: this.SLA_TARGET,
        slaBreached,
        slaMet: !slaBreached,
        totalChecks: service.totalChecks,
        successfulChecks: service.successfulChecks,
        avgLatency: Math.round(service.avgLatency * 100) / 100,
        p95Latency: Math.round(service.p95Latency * 100) / 100,
        p99Latency: Math.round(service.p99Latency * 100) / 100,
        incidents,
        lastChecked: service.lastChecked,
      };
    }).sort((a, b) => a.serviceName.localeCompare(b.serviceName));
  }

  // ── Incidents ───────────────────────────────────────────────────────

  getIncidents(limit = 50): IncidentRecord[] {
    return this.incidents.slice(-limit).reverse();
  }

  // ── Stats ───────────────────────────────────────────────────────────

  getStats(): WatchdogStats {
    const services = Array.from(this.services.values());
    const alerts = Array.from(this.alerts.values());
    const totalUptime = services.length > 0
      ? services.reduce((sum, s) => sum + s.uptime, 0) / services.length
      : 100;

    const slaReports = this.generateSLAReport();
    const slaBreaches = slaReports.filter(r => r.slaBreached).length;

    return {
      totalServices: services.length,
      healthyServices: services.filter(s => s.status === 'healthy').length,
      degradedServices: services.filter(s => s.status === 'degraded').length,
      downServices: services.filter(s => s.status === 'down').length,
      unknownServices: services.filter(s => s.status === 'unknown').length,
      totalAlerts: alerts.length,
      openAlerts: alerts.filter(a => !a.resolvedAt).length,
      unacknowledgedAlerts: alerts.filter(a => !a.acknowledged).length,
      criticalAlerts: alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length,
      overallUptime: Math.round(totalUptime * 1000) / 1000,
      slaBreaches,
      activePolling: this.pollingActive,
    };
  }

  // ── Prometheus Text Export ──────────────────────────────────────────

  exportPrometheusText(): string {
    const lines: string[] = [];
    const stats = this.getStats();

    lines.push('# HELP sentinel_services_total Total watched services');
    lines.push('# TYPE sentinel_services_total gauge');
    lines.push(`sentinel_services_total ${stats.totalServices}`);

    lines.push('# HELP sentinel_services_healthy Healthy services');
    lines.push('# TYPE sentinel_services_healthy gauge');
    lines.push(`sentinel_services_healthy ${stats.healthyServices}`);

    lines.push('# HELP sentinel_services_down Down services');
    lines.push('# TYPE sentinel_services_down gauge');
    lines.push(`sentinel_services_down ${stats.downServices}`);

    lines.push('# HELP sentinel_sla_breaches SLA breaches count');
    lines.push('# TYPE sentinel_sla_breaches gauge');
    lines.push(`sentinel_sla_breaches ${stats.slaBreaches}`);

    lines.push('# HELP sentinel_overall_uptime Overall uptime percentage');
    lines.push('# TYPE sentinel_overall_uptime gauge');
    lines.push(`sentinel_overall_uptime ${stats.overallUptime}`);

    lines.push('');
    lines.push('# HELP sentinel_service_uptime Per-service uptime percentage');
    lines.push('# TYPE sentinel_service_uptime gauge');
    for (const svc of this.services.values()) {
      lines.push(`sentinel_service_uptime{service="${svc.name}",tier="${svc.tier}"} ${svc.uptime}`);
    }

    lines.push('');
    lines.push('# HELP sentinel_service_latency_avg Per-service average latency ms');
    lines.push('# TYPE sentinel_service_latency_avg gauge');
    for (const svc of this.services.values()) {
      lines.push(`sentinel_service_latency_avg{service="${svc.name}"} ${svc.avgLatency}`);
    }

    lines.push('');
    lines.push('# HELP sentinel_service_latency_p95 Per-service p95 latency ms');
    lines.push('# TYPE sentinel_service_latency_p95 gauge');
    for (const svc of this.services.values()) {
      lines.push(`sentinel_service_latency_p95{service="${svc.name}"} ${svc.p95Latency}`);
    }

    return lines.join('\n') + '\n';
  }

  // ── Private ─────────────────────────────────────────────────────────

  private handleStatusChange(service: WatchedService, prevStatus: ServiceStatus): void {
    if (service.status === 'down') {
      this.raiseAlert({
        serviceId: service.id,
        severity: 'critical',
        message: `Service ${service.name} is DOWN (was: ${prevStatus}, consecutive failures: ${service.consecutiveFailures})`,
        channel: 'prometheus',
      });
      this.incidents.push({
        id: uuidv4(),
        serviceId: service.id,
        serviceName: service.name,
        severity: 'critical',
        startedAt: new Date(),
        description: `Service went DOWN from ${prevStatus}`,
      });
    } else if (service.status === 'degraded') {
      this.raiseAlert({
        serviceId: service.id,
        severity: 'warning',
        message: `Service ${service.name} is DEGRADED (${service.consecutiveFailures} consecutive failures)`,
      });
    } else if (service.status === 'healthy' && (prevStatus === 'down' || prevStatus === 'degraded')) {
      this.raiseAlert({
        serviceId: service.id,
        severity: 'info',
        message: `Service ${service.name} recovered to HEALTHY (was: ${prevStatus})`,
      });
      // Resolve open incidents
      for (const incident of this.incidents) {
        if (incident.serviceId === service.id && !incident.resolvedAt) {
          incident.resolvedAt = new Date();
          incident.duration = incident.resolvedAt.getTime() - incident.startedAt.getTime();
        }
      }
    }
  }
}