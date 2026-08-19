import express from 'express';
import db from '../db.js';
import { requireAuth } from '../middleware/authMiddleware.js';
import { monitorWorker } from '../services/monitorWorker.js';

const router = express.Router();

// GET /api/prefixes
router.get('/', requireAuth, (req, res) => {
  const prefixes = db.prepare('SELECT id, prefix, updated_at FROM protected_prefixes ORDER BY prefix ASC').all();
  res.json({
    prefixes,
    total: prefixes.length
  });
});

// POST /api/prefixes/sync
router.post('/sync', requireAuth, async (req, res) => {
  try {
    const result = await monitorWorker.syncProtectedPrefixes();
    const updatedPrefixes = db.prepare('SELECT id, prefix, updated_at FROM protected_prefixes ORDER BY prefix ASC').all();
    res.json({
      success: true,
      message: `Successfully synchronized ${result.count} protected network prefix(es).`,
      prefixes: updatedPrefixes,
      count: result.count
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: `Failed to synchronize prefixes: ${err.message}`
    });
  }
});

export default router;
