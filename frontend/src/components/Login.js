import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
} from '@mui/material';
import { useAuth } from '../auth/AuthContext';
import CheckIcon from '@mui/icons-material/Check';
import CloseIcon from '@mui/icons-material/Close';

function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [buttonState, setButtonState] = useState('idle'); // idle | success | error

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    setButtonState('idle');
    try {
      setButtonState('success');
      // Give the user a brief success animation before the app switches views.
      await login(username, password, { deferSetUserMs: 450 });
    } catch (err) {
      setError(err?.response?.data?.error || err.message || 'Login failed');
      setButtonState('error');
      window.setTimeout(() => setButtonState('idle'), 900);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ minHeight: '70vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Paper sx={{ p: 4, width: 420, maxWidth: '95vw' }}>
        <Typography variant="h5" gutterBottom>
          Sign in to NetLens
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <form onSubmit={onSubmit}>
          <TextField
            label="Username"
            fullWidth
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            sx={{ mb: 2 }}
            autoComplete="username"
          />
          <TextField
            label="Password"
            type="password"
            fullWidth
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            sx={{ mb: 2 }}
            autoComplete="current-password"
          />
          <Button
            type="submit"
            variant="contained"
            fullWidth
            disabled={loading}
            sx={{
              position: 'relative',
              overflow: 'hidden',
              transition: 'background-color 160ms ease, transform 120ms ease',
              '@keyframes loginShake': {
                '0%': { transform: 'translateX(0)' },
                '20%': { transform: 'translateX(-6px)' },
                '40%': { transform: 'translateX(6px)' },
                '60%': { transform: 'translateX(-4px)' },
                '80%': { transform: 'translateX(4px)' },
                '100%': { transform: 'translateX(0)' },
              },
              ...(buttonState === 'success'
                ? { backgroundColor: 'success.main' }
                : buttonState === 'error'
                ? { backgroundColor: 'error.main', animation: 'loginShake 320ms ease' }
                : {}),
            }}
          >
            <Box sx={{ opacity: buttonState === 'idle' ? 1 : 0, transition: 'opacity 120ms ease' }}>Sign in</Box>
            {buttonState !== 'idle' && (
              <Box
                sx={{
                  position: 'absolute',
                  inset: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  pointerEvents: 'none',
                }}
              >
                {buttonState === 'success' ? <CheckIcon /> : <CloseIcon />}
              </Box>
            )}
          </Button>
        </form>
      </Paper>
    </Box>
  );
}

export default Login;
