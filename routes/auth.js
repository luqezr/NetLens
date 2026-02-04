const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const User = require('../models/User');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

function sanitizeUser(user) {
  return {
    id: user._id.toString(),
    username: user.username,
    display_name: user.display_name || '',
    email: user.email || '',
    must_change_password: Boolean(user.must_change_password),
    last_login_at: user.last_login_at,
    created_at: user.createdAt,
    updated_at: user.updatedAt,
  };
}

router.get('/me', async (req, res) => {
  try {
    if (!req.session?.userId) {
      return res.json({ success: true, data: { authenticated: false } });
    }

    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy(() => {});
      return res.json({ success: true, data: { authenticated: false } });
    }

    return res.json({ success: true, data: { authenticated: true, user: sanitizeUser(user) } });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/login', loginLimiter, async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');

    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'username and password are required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    req.session.userId = user._id.toString();
    user.last_login_at = new Date();
    await user.save();

    return res.json({ success: true, data: { user: sanitizeUser(user) } });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/logout', async (req, res) => {
  try {
    if (!req.session) {
      return res.json({ success: true });
    }
    req.session.destroy(() => {
      res.clearCookie('netlens.sid');
      res.json({ success: true });
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

router.patch('/me', async (req, res) => {
  try {
    if (!req.session?.userId) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const display_name = req.body?.display_name;
    const email = req.body?.email;

    const update = {};
    if (display_name !== undefined) update.display_name = String(display_name);
    if (email !== undefined) update.email = String(email);

    const user = await User.findByIdAndUpdate(req.session.userId, { $set: update }, { new: true });
    return res.json({ success: true, data: { user: sanitizeUser(user) } });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/change-password', async (req, res) => {
  try {
    if (!req.session?.userId) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const current_password = String(req.body?.current_password || '');
    const new_password = String(req.body?.new_password || '');

    if (!current_password || !new_password) {
      return res.status(400).json({ success: false, error: 'current_password and new_password are required' });
    }
    if (new_password.length < 8) {
      return res.status(400).json({ success: false, error: 'new_password must be at least 8 characters' });
    }

    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const ok = await bcrypt.compare(current_password, user.password_hash);
    if (!ok) {
      return res.status(400).json({ success: false, error: 'Current password is incorrect' });
    }

    const saltRounds = Number(process.env.BCRYPT_ROUNDS || 12);
    user.password_hash = await bcrypt.hash(new_password, saltRounds);
    user.must_change_password = false;
    await user.save();

    return res.json({ success: true });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
