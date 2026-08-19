import express from 'express';
import { getSettings, updateSettings } from '../db.js';
import { requireAuth } from '../middleware/authMiddleware.js';
import { testCredentials } from '../services/impervaService.js';
import { sendTestEmail } from '../services/emailService.js';
import { monitorWorker } from '../services/monitorWorker.js';

const router = express.Router();

// GET /api/settings
router.get('/', requireAuth, (req, res) => {
  const settings = getSettings();
  // Return settings (mask password indicator if set)
  const safeSettings = {
    ...settings,
    has_smtp_pass: !!settings.smtp_pass,
    has_api_key: !!settings.api_key
  };
  // Don't leak jwt_secret
  delete safeSettings.jwt_secret;
  res.json(safeSettings);
});

// PUT /api/settings
router.put('/', requireAuth, (req, res) => {
  const current = getSettings();
  const updates = { ...req.body };

  // If password field is empty string, don't overwrite if existing pass is set unless explicitly intended
  if (updates.smtp_pass === '' && current.smtp_pass && updates.keep_existing_smtp_pass) {
    delete updates.smtp_pass;
  }
  delete updates.keep_existing_smtp_pass;
  delete updates.jwt_secret;

  const updated = updateSettings(updates);

  // Restart or update worker
  if (updates.monitoring_interval_seconds !== undefined || updates.monitoring_enabled !== undefined) {
    if (updated.monitoring_enabled === 'true') {
      monitorWorker.restart();
    } else {
      monitorWorker.stop();
    }
  }

  res.json({
    success: true,
    message: 'Settings updated successfully',
    settings: {
      ...updated,
      has_smtp_pass: !!updated.smtp_pass,
      has_api_key: !!updated.api_key
    }
  });
});

// POST /api/settings/test-credentials
router.post('/test-credentials', requireAuth, async (req, res) => {
  const { account_id, api_id, api_key } = req.body;
  const current = getSettings();

  const creds = {
    account_id: account_id || current.account_id,
    api_id: api_id || current.api_id,
    api_key: api_key || current.api_key
  };

  const result = await testCredentials(creds);
  if (result.success) {
    res.json(result);
  } else {
    res.status(400).json(result);
  }
});

// POST /api/settings/test-email
router.post('/test-email', requireAuth, async (req, res) => {
  const customSettings = req.body;
  const current = getSettings();

  const mergedSettings = {
    ...current,
    ...customSettings,
    smtp_pass: customSettings.smtp_pass || current.smtp_pass
  };

  try {
    const result = await sendTestEmail(mergedSettings, req.body.recipientEmail);
    res.json({
      success: true,
      message: `Test email sent successfully! Message ID: ${result.messageId}`
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      error: `Failed to send test email: ${err.message}`
    });
  }
});

export default router;
