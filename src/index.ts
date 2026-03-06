/**
 * Sentinel AI — Entry Point
 *
 * Service health monitoring, SLA tracking, and watchdog alerting
 * for the Trancendos mesh. Tracks uptime, latency, and error rates
 * across all mesh services.
 * Zero-cost compliant — no LLM calls.
 *
 * Port: 3021
 * Architecture: Trancendos Industry 6.0 / 2060 Standard
 */

import { app, watchdog } from './api/server';
import { logger } from './utils/logger';

const PORT = Number(process.env.PORT ?? 3021);
const HOST = process.env.HOST ?? '0.0.0.0';

// ── Startup ────────────────────────────────────────────────────────────────

async function bootstrap(): Promise<void> {
  logger.info('Sentinel AI starting up...');

  const server = app.listen(PORT, HOST, () => {
    logger.info(
      { port: PORT, host: HOST, env: process.env.NODE_ENV ?? 'development' },
      '🛡️  Sentinel AI is online — Watchdog is active',
    );
  });

  // ── Periodic SLA Summary (every 30 minutes) ──────────────────────────────
  const SLA_INTERVAL = Number(process.env.SLA_INTERVAL_MS ?? 30 * 60 * 1000);
  const slaTimer = setInterval(() => {
    try {
      const stats = watchdog.getStats();
      const slaReports = watchdog.generateSLAReport();
      const breached = slaReports.filter(r => !r.slaBreached === false);

      logger.info(
        {
          totalServices: stats.totalServices,
          healthyServices: stats.healthyServices,
          degradedServices: stats.degradedServices,
          downServices: stats.downServices,
          openAlerts: stats.openAlerts,
          slaBreaches: breached.length,
        },
        '🛡️  Sentinel periodic SLA summary',
      );

      if (stats.downServices > 0) {
        logger.warn({ downServices: stats.downServices }, '⚠️  Services are DOWN — immediate attention required');
      }
    } catch (err) {
      logger.error({ err }, 'Periodic SLA summary failed');
    }
  }, SLA_INTERVAL);

  // ── Graceful Shutdown ────────────────────────────────────────────────────
  const shutdown = (signal: string) => {
    logger.info({ signal }, 'Shutdown signal received');
    clearInterval(slaTimer);
    server.close(() => {
      logger.info('Sentinel AI shut down cleanly');
      process.exit(0);
    });
    setTimeout(() => {
      logger.warn('Forced shutdown after timeout');
      process.exit(1);
    }, 10_000);
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