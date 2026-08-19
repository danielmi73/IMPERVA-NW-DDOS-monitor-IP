import express from 'express';
import { stringify } from 'csv-stringify/sync';
import db from '../db.js';
import { requireAuth } from '../middleware/authMiddleware.js';

const router = express.Router();

// GET /api/logs
router.get('/', requireAuth, (req, res) => {
  const { ip, network_range, status, startDate, endDate, limit = 100, page = 1 } = req.query;

  let query = 'SELECT * FROM blocking_logs WHERE 1=1';
  let countQuery = 'SELECT COUNT(*) as count FROM blocking_logs WHERE 1=1';
  const params = [];
  const countParams = [];

  if (ip) {
    query += ' AND source_ip LIKE ?';
    countQuery += ' AND source_ip LIKE ?';
    const val = `%${ip.trim()}%`;
    params.push(val);
    countParams.push(val);
  }

  if (network_range) {
    query += ' AND network_range LIKE ?';
    countQuery += ' AND network_range LIKE ?';
    const val = `%${network_range.trim()}%`;
    params.push(val);
    countParams.push(val);
  }

  if (status) {
    query += ' AND notification_status = ?';
    countQuery += ' AND notification_status = ?';
    params.push(status);
    countParams.push(status);
  }

  if (startDate) {
    query += ' AND timestamp >= ?';
    countQuery += ' AND timestamp >= ?';
    params.push(startDate);
    countParams.push(startDate);
  }

  if (endDate) {
    query += ' AND timestamp <= ?';
    countQuery += ' AND timestamp <= ?';
    params.push(endDate);
    countParams.push(endDate);
  }

  query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  const parsedLimit = Math.min(500, Math.max(1, parseInt(limit, 10) || 100));
  const offset = (Math.max(1, parseInt(page, 10) || 1) - 1) * parsedLimit;
  params.push(parsedLimit, offset);

  const logs = db.prepare(query).all(...params);
  const totalCount = db.prepare(countQuery).get(...countParams).count;

  res.json({
    logs,
    pagination: {
      total: totalCount,
      page: parseInt(page, 10) || 1,
      limit: parsedLimit,
      totalPages: Math.ceil(totalCount / parsedLimit) || 1
    }
  });
});

// GET /api/logs/stats
router.get('/stats', requireAuth, (req, res) => {
  const totalEvents = db.prepare('SELECT COUNT(*) as count FROM blocking_logs').get().count;
  const uniqueIps = db.prepare('SELECT COUNT(DISTINCT source_ip) as count FROM blocking_logs').get().count;
  const emailsSent = db.prepare('SELECT COUNT(*) as count FROM blocking_logs WHERE notification_sent = 1').get().count;
  const latestEvent = db.prepare('SELECT timestamp, source_ip, network_range, bandwidth_human FROM blocking_logs ORDER BY timestamp DESC LIMIT 1').get();
  const peakBandwidthRow = db.prepare('SELECT bandwidth_bps, bandwidth_human, source_ip FROM blocking_logs ORDER BY bandwidth_bps DESC LIMIT 1').get();

  res.json({
    totalEvents,
    uniqueIps,
    emailsSent,
    latestEvent: latestEvent || null,
    peakBandwidth: peakBandwidthRow ? peakBandwidthRow.bandwidth_human : '0 bps'
  });
});

// DELETE /api/logs
router.delete('/', requireAuth, (req, res) => {
  db.prepare('DELETE FROM blocking_logs').run();
  res.json({ success: true, message: 'All blocking event logs have been cleared.' });
});

// GET /api/logs/export-csv
router.get('/export-csv', requireAuth, (req, res) => {
  const logs = db.prepare('SELECT timestamp, source_ip, description, network_range, bandwidth_bps, bandwidth_human, notification_status FROM blocking_logs ORDER BY timestamp DESC').all();

  const csvData = logs.map(l => [
    l.timestamp,
    l.source_ip,
    l.description || '',
    l.network_range,
    l.bandwidth_bps,
    l.bandwidth_human,
    l.notification_status
  ]);

  const output = stringify([
    ['Timestamp', 'Blocked Source IP', 'Description', 'Network Range', 'Bandwidth (bps)', 'Bandwidth (Formatted)', 'Notification Status'],
    ...csvData
  ]);

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="blocking_events.csv"');
  res.send(output);
});

export default router;
