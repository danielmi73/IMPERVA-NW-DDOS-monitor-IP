import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db, { getSettings } from '../db.js';
import { requireAuth } from '../middleware/authMiddleware.js';

const router = express.Router();

export function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, message: 'Password is required' };
  }
  if (password.length < 6) {
    return { valid: false, message: 'Password must be at least 6 characters long' };
  }
  if (!/\d/.test(password)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  if (!/[!@#$%^&*(),.?":{}|<>_\-\\\/+=~`\[\]]/.test(password)) {
    return { valid: false, message: 'Password must contain at least one special character' };
  }
  return { valid: true };
}

// GET /api/auth/status
router.get('/status', (req, res) => {
  const admin = db.prepare('SELECT id FROM admin WHERE id = 1').get();
  const isSetup = !!admin;

  let authenticated = false;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const settings = getSettings();
    try {
      jwt.verify(token, settings.jwt_secret || 'default-secret');
      authenticated = true;
    } catch {
      authenticated = false;
    }
  }

  res.json({
    isSetup,
    authenticated
  });
});

// POST /api/auth/setup (First time admin registration)
router.post('/setup', async (req, res) => {
  const existingAdmin = db.prepare('SELECT id FROM admin WHERE id = 1').get();
  if (existingAdmin) {
    return res.status(400).json({ error: 'Admin account has already been set up. Please log in.' });
  }

  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  const validation = validatePassword(password);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.message });
  }

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);

  db.prepare(`
    INSERT INTO admin (id, password_hash, created_at, updated_at)
    VALUES (1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `).run(hash);

  const settings = getSettings();
  const token = jwt.sign({ id: 1, role: 'admin' }, settings.jwt_secret || 'default-secret', { expiresIn: '7d' });

  res.json({
    success: true,
    message: 'Admin password configured successfully.',
    token
  });
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const admin = db.prepare('SELECT password_hash FROM admin WHERE id = 1').get();
  if (!admin) {
    return res.status(400).json({ error: 'Admin is not configured yet. Please complete initial setup.' });
  }

  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }

  const isMatch = await bcrypt.compare(password, admin.password_hash);
  if (!isMatch) {
    return res.status(401).json({ error: 'Invalid password. Please try again.' });
  }

  const settings = getSettings();
  const token = jwt.sign({ id: 1, role: 'admin' }, settings.jwt_secret || 'default-secret', { expiresIn: '7d' });

  res.json({
    success: true,
    message: 'Login successful',
    token
  });
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'New passwords do not match' });
  }

  const validation = validatePassword(newPassword);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.message });
  }

  const admin = db.prepare('SELECT password_hash FROM admin WHERE id = 1').get();
  if (!admin) {
    return res.status(400).json({ error: 'Admin user not found' });
  }

  const isMatch = await bcrypt.compare(currentPassword, admin.password_hash);
  if (!isMatch) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  const salt = await bcrypt.genSalt(10);
  const newHash = await bcrypt.hash(newPassword, salt);

  db.prepare('UPDATE admin SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1').run(newHash);

  res.json({
    success: true,
    message: 'Admin password changed successfully'
  });
});

export default router;
