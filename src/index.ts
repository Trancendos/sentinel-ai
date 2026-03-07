/**
 * Sentinel AI — Entry Point
 *
 * Service health monitoring, SLA tracking, active health polling,
 * incident tracking, and watchdog alerting for the Trancendos mesh.
 * Full 24-service ecosystem coverage with Prometheus-AI integration.
 * Zero-cost compliant — no LLM calls.
 *
 * Port: 3021
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { app, watchdog } from './api/server';
import { logger } from './utils/logger';

const PORT = Number(process.env.PORT ?? 3021);
const HOST = process.env.HOST ?? '0.0.0.0';
const AUTO_POLL = process.env.AUTO_POLL !== 'false'; // default: true

// ── Startup ──────────────────────────────────────────────────────────────────

async function bootstrap(): Promise<void> {
  logger.info('Sentinel AI starting up...');

  const server = app.listen(PORT, HOST, () => {
    logger.info(
      { port: PORT, host: HOST, env: process.env.NODE_ENV ?? 'development' },
      '🛡️  Sentinel AI is online — Watchdog is active',
    );
  });

  // ── Auto-start active health polling ─────────────────────────────────────
  if (AUTO_POLL) {
    // Delay polling start to allow other services to boot
    const POLL_DELAY = Number(process.env.POLL_START_DELAY_MS ?? 10_000);
    setTimeout(() => {
      watchdog.startPolling();
      logger.info({ delay: POLL_DELAY }, '🛡️  Active health polling auto-started');
    }, POLL_DELAY);
  }

  // ── Periodic SLA Summary (every 30 minutes) ─────────────────────────────
  const SLA_INTERVAL = Number(process.env.SLA_INTERVAL_MS ?? 30 * 60 * 1000);
  const slaTimer = setInterval(() => {
    try {
      const stats = watchdog.getStats();
      const slaReports = watchdog.generateSLAReport();
      const breached = slaReports.filter(r => r.slaBreached);

      logger.info(
        {
          totalServices: stats.totalServices,
          healthyServices: stats.healthyServices,
          degradedServices: stats.degradedServices,
          downServices: stats.downServices,
          unknownServices: stats.unknownServices,
          openAlerts: stats.openAlerts,
          slaBreaches: breached.length,
          overallUptime: stats.overallUptime,
          activePolling: stats.activePolling,
        },
        '🛡️  Sentinel periodic SLA summary',
      );

      if (stats.downServices > 0) {
        logger.warn({ downServices: stats.downServices }, '⚠️  Services are DOWN — immediate attention required');
      }

      if (breached.length > 0) {
        logger.warn(
          { breaches: breached.map(b => `${b.serviceName}: ${b.uptimePercent}%`) },
          '⚠️  SLA breaches detected'
        );
      }
    } catch (err) {
      logger.error({ err }, 'Periodic SLA summary failed');
    }
  }, SLA_INTERVAL);

  // ── Graceful Shutdown ────────────────────────────────────────────────────
  const shutdown = (signal: string) => {
    logger.info({ signal }, 'Shutdown signal received');
    clearInterval(slaTimer);
    watchdog.stopPolling();
    server.close(() => {
      logger.info('Sentinel AI shut down cleanly');
      process.exit(0);
    });
    setTimeout(() => {
      logger.warn('Forced shutdown after timeout');
      process.exit(1);
    }, 30_000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    logger.error({ err }, 'Uncaught exception');
    process.exit(1);
  });

  process.on('unhandledRejection', (reason) => {
    logger.error({ reason }, 'Unhandled rejection');
    process.exit(1);
  });
}

bootstrap().catch((err) => {
  logger.error({ err }, 'Bootstrap failed');
  process.exit(1);
});