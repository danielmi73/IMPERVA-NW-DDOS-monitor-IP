import db, { getSettings } from '../db.js';
import { fetchProtectedNetworks, fetchBlockedIpsForPrefix, formatBandwidth } from './impervaService.js';
import { sendBlockAlertEmail } from './emailService.js';

class MonitorWorker {
  constructor() {
    this.timer = null;
    this.isChecking = false;
    this.lastCheckTime = null;
    this.lastCheckStatus = 'Idle';
    this.lastError = null;
    this.consecutiveFailures = 0;
    // Map to keep track of recently alerted IPs to avoid spam: ip -> timestamp
    this.recentAlerts = new Map();
  }

  start() {
    this.stop();
    const settings = getSettings();
    if (settings.monitoring_enabled !== 'true') {
      console.log('[MonitorWorker] Monitoring is disabled in settings.');
      this.lastCheckStatus = 'Stopped (Disabled)';
      return;
    }

    const intervalSeconds = Math.max(10, parseInt(settings.monitoring_interval_seconds || '60', 10));
    console.log(`[MonitorWorker] Starting monitor loop with interval: ${intervalSeconds}s`);
    this.lastCheckStatus = 'Running';

    // Run initial check shortly after startup
    setTimeout(() => this.runCheckCycle(), 2000);

    this.timer = setInterval(() => {
      this.runCheckCycle();
    }, intervalSeconds * 1000);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.lastCheckStatus = 'Stopped';
    console.log('[MonitorWorker] Monitor worker stopped.');
  }

  restart() {
    this.stop();
    this.start();
  }

  getStatus() {
    const settings = getSettings();
    return {
      running: this.timer !== null && settings.monitoring_enabled === 'true',
      enabled: settings.monitoring_enabled === 'true',
      intervalSeconds: parseInt(settings.monitoring_interval_seconds || '60', 10),
      lastCheckTime: this.lastCheckTime,
      lastCheckStatus: this.lastCheckStatus,
      lastError: this.lastError,
      isChecking: this.isChecking
    };
  }

  /**
   * Sync protected prefixes from Imperva API to database
   */
  async syncProtectedPrefixes() {
    try {
      const prefixesData = await fetchProtectedNetworks();
      if (!prefixesData || typeof prefixesData !== 'object') {
        throw new Error('Invalid response received from Imperva prefixes API');
      }

      const insertStmt = db.prepare(`
        INSERT INTO protected_prefixes (id, prefix, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET prefix=excluded.prefix, updated_at=CURRENT_TIMESTAMP
      `);

      const currentIds = Object.keys(prefixesData);
      const syncTx = db.transaction(() => {
        for (const [id, prefix] of Object.entries(prefixesData)) {
          insertStmt.run(String(id), String(prefix));
        }
        // Optionally remove old ones if needed
        if (currentIds.length > 0) {
          const placeholders = currentIds.map(() => '?').join(',');
          db.prepare(`DELETE FROM protected_prefixes WHERE id NOT IN (${placeholders})`).run(...currentIds);
        }
      });

      syncTx();
      console.log(`[MonitorWorker] Successfully synced ${currentIds.length} protected network prefixes.`);
      return { success: true, count: currentIds.length, prefixes: prefixesData };
    } catch (err) {
      console.error('[MonitorWorker] Failed to sync protected prefixes:', err.message);
      throw err;
    }
  }

  /**
   * Execute one monitoring check cycle
   */
  async runCheckCycle(force = false) {
    if (this.isChecking) {
      console.log('[MonitorWorker] Check cycle already in progress. Skipping.');
      return;
    }

    const settings = getSettings();
    if (!force && settings.monitoring_enabled !== 'true') {
      return;
    }

    if (!settings.account_id || !settings.api_id || !settings.api_key) {
      this.lastError = 'Imperva API credentials not fully configured in Admin Settings.';
      this.lastCheckStatus = 'Credentials Missing';
      return;
    }

    this.isChecking = true;
    this.lastCheckTime = new Date().toISOString();
    this.lastCheckStatus = 'Checking prefixes...';
    this.lastError = null;

    try {
      // 1. Get protected prefixes from DB
      let prefixes = db.prepare('SELECT id, prefix FROM protected_prefixes').all();
      if (prefixes.length === 0) {
        console.log('[MonitorWorker] No local prefixes found. Attempting to sync from Imperva API...');
        await this.syncProtectedPrefixes();
        prefixes = db.prepare('SELECT id, prefix FROM protected_prefixes').all();
      }

      // 2. Get active monitored IPs
      const monitoredIps = db.prepare('SELECT id, ip_address, description, assigned_prefixes FROM monitored_ips').all();

      if (monitoredIps.length === 0) {
        this.lastCheckStatus = 'Idle (No monitored IPs configured)';
        this.isChecking = false;
        return;
      }

      // Create lookup map of monitored IPs: ip_address -> { id, ip_address, description, assigned_prefixes }
      const ipMap = new Map();
      for (const item of monitoredIps) {
        let assigned = ['*'];
        try {
          assigned = JSON.parse(item.assigned_prefixes || '["*"]');
        } catch {
          assigned = ['*'];
        }
        ipMap.set(item.ip_address.trim(), {
          ...item,
          assignedPrefixes: assigned
        });
      }

      const cooldownMs = parseInt(settings.cooldown_minutes || '15', 10) * 60 * 1000;
      const now = Date.now();
      const detectedBlockedEvents = [];
      const logInsertStmt = db.prepare(`
        INSERT INTO blocking_logs 
        (timestamp, source_ip, bandwidth_bps, bandwidth_human, network_range, description, notification_sent, notification_status, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      // 3. For each prefix, query top-table
      for (const p of prefixes) {
        const prefixId = String(p.id);
        const prefixCidr = String(p.prefix);

        // Check if any monitored IP applies to this prefix
        const relevantIps = Array.from(ipMap.values()).filter(ip => {
          if (ip.assignedPrefixes.includes('*')) return true;
          if (ip.assignedPrefixes.includes(prefixId)) return true;
          if (ip.assignedPrefixes.includes(prefixCidr)) return true;
          return false;
        });

        if (relevantIps.length === 0) continue;

        try {
          // Lookback interval window (default past 15 mins to catch active blocks)
          const lookbackMs = 15 * 60 * 1000;
          const topTableData = await fetchBlockedIpsForPrefix(prefixCidr, now - lookbackMs, now);

          if (topTableData && Array.isArray(topTableData.stats)) {
            for (const stat of topTableData.stats) {
              const blockedIp = stat.object?.trim();
              const bandwidth = stat.value || 0;

              if (ipMap.has(blockedIp)) {
                const ipConfig = ipMap.get(blockedIp);
                // Check if this IP is mapped to this prefix
                const applies = ipConfig.assignedPrefixes.includes('*') ||
                                ipConfig.assignedPrefixes.includes(prefixId) ||
                                ipConfig.assignedPrefixes.includes(prefixCidr);

                if (applies) {
                  const eventTime = new Date().toISOString();
                  const bwHuman = formatBandwidth(bandwidth);

                  // Check cooldown for email alerting
                  const lastAlert = this.recentAlerts.get(blockedIp) || 0;
                  const isCoolingDown = (now - lastAlert) < cooldownMs;

                  const event = {
                    timestamp: eventTime,
                    source_ip: blockedIp,
                    bandwidth_bps: bandwidth,
                    bandwidth_human: bwHuman,
                    network_range: prefixCidr,
                    description: ipConfig.description || '',
                    notification_sent: 0,
                    notification_status: isCoolingDown ? 'Cooldown Suppressed' : 'Pending',
                    raw_data: JSON.stringify(stat),
                    shouldAlert: !isCoolingDown
                  };

                  detectedBlockedEvents.push(event);

                  if (!isCoolingDown) {
                    this.recentAlerts.set(blockedIp, now);
                  }
                }
              }
            }
          }
        } catch (prefixErr) {
          console.warn(`[MonitorWorker] Error querying top-table for prefix ${prefixCidr}:`, prefixErr.message);
        }
      }

      // 4. Record all detected events to database
      if (detectedBlockedEvents.length > 0) {
        const eventsToAlert = detectedBlockedEvents.filter(e => e.shouldAlert);
        let emailResult = { success: false, reason: 'No alertable events' };

        if (eventsToAlert.length > 0) {
          console.log(`[MonitorWorker] ⚠️ Block detected for ${eventsToAlert.length} monitored IP(s). Dispatching alert...`);
          emailResult = await sendBlockAlertEmail(eventsToAlert);
        }

        // Insert log rows with final email status
        const insertLogsTx = db.transaction((events) => {
          for (const ev of events) {
            let status = ev.notification_status;
            let sentFlag = 0;
            if (ev.shouldAlert) {
              if (emailResult.success) {
                status = 'Sent';
                sentFlag = 1;
              } else {
                status = `Failed (${emailResult.error || emailResult.reason || 'Unknown error'})`;
                sentFlag = 0;
              }
            }
            logInsertStmt.run(
              ev.timestamp,
              ev.source_ip,
              ev.bandwidth_bps,
              ev.bandwidth_human,
              ev.network_range,
              ev.description,
              sentFlag,
              status,
              ev.raw_data
            );
          }
        });

        insertLogsTx(detectedBlockedEvents);
        this.lastCheckStatus = `Completed (Detected ${detectedBlockedEvents.length} blocked event(s))`;
      } else {
        this.lastCheckStatus = 'Healthy (No blocked monitored IPs detected)';
      }

      this.consecutiveFailures = 0;
    } catch (err) {
      this.consecutiveFailures++;
      this.lastError = err.message;
      this.lastCheckStatus = `Error: ${err.message}`;
      console.error('[MonitorWorker] Check cycle error:', err);
    } finally {
      this.isChecking = false;
    }
  }

  /**
   * Simulate a DDoS block detection event for testing purposes
   */
  async simulateBlockEvent(customEvents = null) {
    const monitoredIps = db.prepare('SELECT id, ip_address, description, assigned_prefixes FROM monitored_ips').all();
    const prefixes = db.prepare('SELECT id, prefix FROM protected_prefixes').all();

    let targetEvents = [];

    if (customEvents && Array.isArray(customEvents) && customEvents.length > 0) {
      targetEvents = customEvents;
    } else if (monitoredIps.length > 0) {
      const samplePrefix = prefixes.length > 0 ? prefixes[0].prefix : '142.198.93.0/24';
      targetEvents = monitoredIps.slice(0, 2).map((item, idx) => ({
        timestamp: new Date().toISOString(),
        source_ip: item.ip_address,
        bandwidth_bps: (idx + 1) * 28500000.5,
        bandwidth_human: formatBandwidth((idx + 1) * 28500000.5),
        network_range: samplePrefix,
        description: item.description || 'Test Simulated IP',
        raw_data: JSON.stringify({ object: item.ip_address, value: (idx + 1) * 28500000.5, simulated: true })
      }));
    } else {
      // Create a temporary sample
      targetEvents = [{
        timestamp: new Date().toISOString(),
        source_ip: '195.128.248.33',
        bandwidth_bps: 61185365.33,
        bandwidth_human: formatBandwidth(61185365.33),
        network_range: '45.223.249.0/24',
        description: 'Simulated Attack Node',
        raw_data: JSON.stringify({ object: '195.128.248.33', value: 61185365.33, simulated: true })
      }];
    }

    // Dispatch email
    const emailResult = await sendBlockAlertEmail(targetEvents);

    // Record logs in DB
    const logInsertStmt = db.prepare(`
      INSERT INTO blocking_logs 
      (timestamp, source_ip, bandwidth_bps, bandwidth_human, network_range, description, notification_sent, notification_status, raw_data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertTx = db.transaction(() => {
      for (const ev of targetEvents) {
        logInsertStmt.run(
          ev.timestamp,
          ev.source_ip,
          ev.bandwidth_bps,
          ev.bandwidth_human,
          ev.network_range,
          ev.description,
          emailResult.success ? 1 : 0,
          emailResult.success ? 'Sent' : `Failed (${emailResult.error || emailResult.reason || 'SMTP Error'})`,
          ev.raw_data
        );
      }
    });

    insertTx();

    return {
      success: true,
      simulatedEvents: targetEvents,
      emailResult
    };
  }
}

export const monitorWorker = new MonitorWorker();
export default monitorWorker;
