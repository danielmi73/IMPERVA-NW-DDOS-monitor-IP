import express from 'express';
import multer from 'multer';
import { parse } from 'csv-parse/sync';
import { stringify } from 'csv-stringify/sync';
import db from '../db.js';
import { requireAuth } from '../middleware/authMiddleware.js';

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

// Basic IPv4 & IPv6 validator
export function isValidIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();
  // IPv4
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  // IPv6
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:$|^:(:[0-9a-fA-F]{1,4}){1,7}$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(trimmed) || ipv6Regex.test(trimmed);
}

// GET /api/ips
router.get('/', requireAuth, (req, res) => {
  const search = req.query.search ? `%${req.query.search.trim()}%` : null;
  let query = 'SELECT id, ip_address, description, assigned_prefixes, created_at, updated_at FROM monitored_ips';
  const params = [];

  if (search) {
    query += ' WHERE ip_address LIKE ? OR description LIKE ?';
    params.push(search, search);
  }
  query += ' ORDER BY created_at DESC';

  const rows = db.prepare(query).all(...params);
  const ips = rows.map(r => {
    let prefixes = ['*'];
    try {
      prefixes = JSON.parse(r.assigned_prefixes || '["*"]');
    } catch {
      prefixes = ['*'];
    }
    return {
      ...r,
      assigned_prefixes: prefixes
    };
  });

  res.json({ ips, total: ips.length });
});

// POST /api/ips
router.post('/', requireAuth, (req, res) => {
  const { ip_address, description, assigned_prefixes } = req.body;

  if (!ip_address || !isValidIp(ip_address)) {
    return res.status(400).json({ error: 'Invalid IP address format' });
  }

  const cleanIp = ip_address.trim();
  const prefixesJson = JSON.stringify(Array.isArray(assigned_prefixes) && assigned_prefixes.length > 0 ? assigned_prefixes : ['*']);

  try {
    const result = db.prepare(`
      INSERT INTO monitored_ips (ip_address, description, assigned_prefixes, created_at, updated_at)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).run(cleanIp, (description || '').trim(), prefixesJson);

    const created = db.prepare('SELECT * FROM monitored_ips WHERE id = ?').get(result.lastInsertRowid);
    res.json({
      success: true,
      message: 'Monitored IP added successfully',
      ip: {
        ...created,
        assigned_prefixes: JSON.parse(created.assigned_prefixes || '["*"]')
      }
    });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(400).json({ error: `IP ${cleanIp} is already in the monitoring list.` });
    }
    res.status(500).json({ error: `Failed to add IP: ${err.message}` });
  }
});

// PUT /api/ips/:id
router.put('/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { ip_address, description, assigned_prefixes } = req.body;

  if (!ip_address || !isValidIp(ip_address)) {
    return res.status(400).json({ error: 'Invalid IP address format' });
  }

  const cleanIp = ip_address.trim();
  const prefixesJson = JSON.stringify(Array.isArray(assigned_prefixes) && assigned_prefixes.length > 0 ? assigned_prefixes : ['*']);

  try {
    const result = db.prepare(`
      UPDATE monitored_ips 
      SET ip_address = ?, description = ?, assigned_prefixes = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(cleanIp, (description || '').trim(), prefixesJson, id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Monitored IP record not found' });
    }

    const updated = db.prepare('SELECT * FROM monitored_ips WHERE id = ?').get(id);
    res.json({
      success: true,
      message: 'Monitored IP updated successfully',
      ip: {
        ...updated,
        assigned_prefixes: JSON.parse(updated.assigned_prefixes || '["*"]')
      }
    });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(400).json({ error: `IP ${cleanIp} is already configured in another record.` });
    }
    res.status(500).json({ error: `Failed to update IP: ${err.message}` });
  }
});

// DELETE /api/ips/:id
router.delete('/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const result = db.prepare('DELETE FROM monitored_ips WHERE id = ?').run(id);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'Monitored IP record not found' });
  }

  res.json({ success: true, message: 'Monitored IP removed successfully' });
});

// POST /api/ips/import-csv
router.post('/import-csv', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file && !req.body.csvText) {
    return res.status(400).json({ error: 'No CSV file or text content provided' });
  }

  const csvContent = req.file ? req.file.buffer.toString('utf8') : req.body.csvText;

  let records;
  try {
    records = parse(csvContent, {
      columns: false,
      skip_empty_lines: true,
      trim: true
    });
  } catch (err) {
    return res.status(400).json({ error: `CSV parse error: ${err.message}` });
  }

  if (records.length === 0) {
    return res.status(400).json({ error: 'CSV file is empty' });
  }

  // Check if first row is a header like ["IP", "Description", ...]
  let startIndex = 0;
  const firstRowFirstCol = String(records[0][0]).toLowerCase();
  if (firstRowFirstCol.includes('ip') || firstRowFirstCol.includes('address')) {
    startIndex = 1;
  }

  const insertStmt = db.prepare(`
    INSERT INTO monitored_ips (ip_address, description, assigned_prefixes, created_at, updated_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ON CONFLICT(ip_address) DO UPDATE SET 
      description = excluded.description,
      assigned_prefixes = CASE WHEN excluded.assigned_prefixes != '["*"]' THEN excluded.assigned_prefixes ELSE monitored_ips.assigned_prefixes END,
      updated_at = CURRENT_TIMESTAMP
  `);

  let addedCount = 0;
  let skippedCount = 0;
  const errors = [];

  const importTx = db.transaction(() => {
    for (let i = startIndex; i < records.length; i++) {
      const row = records[i];
      const ip = row[0]?.trim();
      const description = row[1]?.trim() || '';
      let assignedPrefixes = ['*'];

      if (row[2]) {
        try {
          const rawPrefixes = row[2].split(';').map(p => p.trim()).filter(Boolean);
          if (rawPrefixes.length > 0) assignedPrefixes = rawPrefixes;
        } catch {
          assignedPrefixes = ['*'];
        }
      }

      if (!isValidIp(ip)) {
        errors.push(`Row ${i + 1}: Invalid IP '${ip}'`);
        skippedCount++;
        continue;
      }

      insertStmt.run(ip, description, JSON.stringify(assignedPrefixes));
      addedCount++;
    }
  });

  try {
    importTx();
    res.json({
      success: true,
      message: `CSV import finished. Processed: ${addedCount}, Skipped: ${skippedCount}`,
      importedCount: addedCount,
      skippedCount,
      errors
    });
  } catch (err) {
    res.status(500).json({ error: `Database error during import: ${err.message}` });
  }
});

// GET /api/ips/export-csv
router.get('/export-csv', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT ip_address, description, assigned_prefixes, created_at FROM monitored_ips ORDER BY ip_address ASC').all();
  
  const csvData = rows.map(r => {
    let prefixes = ['*'];
    try {
      prefixes = JSON.parse(r.assigned_prefixes || '["*"]');
    } catch {
      prefixes = ['*'];
    }
    return [
      r.ip_address,
      r.description || '',
      prefixes.join(';'),
      r.created_at
    ];
  });

  const output = stringify([['IP Address', 'Description', 'Assigned Prefixes', 'Date Added'], ...csvData]);

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="monitored_ips.csv"');
  res.send(output);
});

export default router;
