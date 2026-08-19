import express from 'express';
import { requireAuth } from '../middleware/authMiddleware.js';
import { monitorWorker } from '../services/monitorWorker.js';
import { updateSettings } from '../db.js';

const router = express.Router();

// GET /api/monitor/status
router.get('/status', requireAuth, (req, res) => {
  res.json(monitorWorker.getStatus());
});

// POST /api/monitor/toggle
router.post('/toggle', requireAuth, (req, res) => {
  const { enabled } = req.body;
  const isEnabled = enabled === true || enabled === 'true';

  updateSettings({ monitoring_enabled: isEnabled ? 'true' : 'false' });

  if (isEnabled) {
    monitorWorker.start();
  } else {
    monitorWorker.stop();
  }

  res.json({
    success: true,
    message: isEnabled ? 'Monitoring engine started' : 'Monitoring engine stopped',
    status: monitorWorker.getStatus()
  });
});

// POST /api/monitor/check-now
router.post('/check-now', requireAuth, async (req, res) => {
  try {
    await monitorWorker.runCheckCycle(true);
    res.json({
      success: true,
      message: 'Monitoring check cycle completed',
      status: monitorWorker.getStatus()
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: `Check cycle failed: ${err.message}`
    });
  }
});

// POST /api/monitor/simulate
router.post('/simulate', requireAuth, async (req, res) => {
  try {
    const result = await monitorWorker.simulateBlockEvent(req.body.customEvents);
    res.json({
      success: true,
      message: 'Simulated DDoS block event created and processed.',
      result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: `Simulation failed: ${err.message}`
    });
  }
});

export default router;
