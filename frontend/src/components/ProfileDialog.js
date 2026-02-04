import React, { useEffect, useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Alert,
  Box,
  Typography,
} from '@mui/material';
import { changePassword, updateProfile } from '../services/api';
import { useAuth } from '../auth/AuthContext';

function ProfileDialog({ open, onClose }) {
  const { user, refresh } = useAuth();
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const [message, setMessage] = useState(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDisplayName(user?.display_name || '');
    setEmail(user?.email || '');
  }, [user, open]);

  const handleSaveProfile = async () => {
    setSaving(true);
    setMessage(null);
    try {
      await updateProfile({ display_name: displayName, email });
      await refresh();
      setMessage({ severity: 'success', text: 'Profile updated.' });
    } catch (e) {
      setMessage({ severity: 'error', text: e?.response?.data?.error || e.message || 'Failed to update profile' });
    } finally {
      setSaving(false);
    }
  };

  const handleChangePassword = async () => {
    setSaving(true);
    setMessage(null);
    try {
      await changePassword({ current_password: currentPassword, new_password: newPassword });
      setCurrentPassword('');
      setNewPassword('');
      await refresh();
      setMessage({ severity: 'success', text: 'Password changed.' });
    } catch (e) {
      setMessage({ severity: 'error', text: e?.response?.data?.error || e.message || 'Failed to change password' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Profile</DialogTitle>
      <DialogContent>
        {message && (
          <Alert severity={message.severity} sx={{ mb: 2 }}>
            {message.text}
          </Alert>
        )}

        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Account
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <TextField label="Username" value={user?.username || ''} fullWidth disabled />
        </Box>

        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Profile information
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap' }}>
          <TextField
            label="Display name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            fullWidth
          />
          <TextField
            label="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            fullWidth
          />
        </Box>

        <Button variant="outlined" onClick={handleSaveProfile} disabled={saving}>
          Save profile
        </Button>

        <Box sx={{ mt: 3 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Change password
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <TextField
              label="Current password"
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              fullWidth
              autoComplete="current-password"
            />
            <TextField
              label="New password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              fullWidth
              autoComplete="new-password"
              helperText="At least 8 characters"
            />
          </Box>

          <Box sx={{ mt: 2 }}>
            <Button variant="contained" onClick={handleChangePassword} disabled={saving}>
              Change password
            </Button>
          </Box>
        </Box>

        {user?.must_change_password && (
          <Alert severity="warning" sx={{ mt: 3 }}>
            This account is using the default password. Please change it now.
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

export default ProfileDialog;
