import React, { useEffect, useRef, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  LinearProgress,
  Typography,
} from '@mui/material';
import { getScanLiveLog } from '../services/api';

export default function ScanLiveLogDialog({ open, onClose }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [cursor, setCursor] = useState(0);
  const [lines, setLines] = useState([]);
  const [running, setRunning] = useState(false);
  const preRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    setLines([]);
    setCursor(0);
    setError(null);
  }, [open]);

  useEffect(() => {
    if (!open) return;

    let cancelled = false;

    const tick = async () => {
      try {
        setLoading(true);
        const res = await getScanLiveLog({ since: cursor, limit: 400 });
        if (cancelled) return;
        const data = res?.data?.data;
        setRunning(Boolean(data?.running));

        const items = Array.isArray(data?.items) ? data.items : [];
        if (items.length > 0) {
          setLines((prev) => {
            const next = prev.concat(items.map((i) => {
              const ts = i?.ts ? new Date(i.ts).toLocaleTimeString() : '';
              const stream = i?.stream || '';
              const text = i?.text || '';
              return ts ? `${ts} [${stream}] ${text}` : `[${stream}] ${text}`;
            }));
            // cap in UI
            return next.slice(-2000);
          });
        }

        // Always advance the cursor if the server returned a next_since.
        // This prevents the UI from getting stuck if the buffer was trimmed.
        const nextSince = Number(data?.next_since);
        if (Number.isFinite(nextSince) && nextSince >= 0) {
          setCursor(nextSince);
        }

        setError(null);
      } catch (e) {
        if (cancelled) return;
        setError(e?.response?.data?.error || e.message || 'Failed to load live log');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    tick();
    const interval = setInterval(tick, 1000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [open, cursor]);

  useEffect(() => {
    if (!open) return;
    const el = preRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [open, lines.length]);

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>Live log</DialogTitle>
      <DialogContent dividers>
        {loading && <LinearProgress sx={{ mb: 2 }} />}
        {error && <Alert severity="warning" sx={{ mb: 2 }}>{error}</Alert>}

        {!running && (
          <Alert severity="info" sx={{ mb: 2 }}>
            Live log is only available while a scan is running on this server instance.
          </Alert>
        )}

        <Box
          component="pre"
          ref={preRef}
          sx={{
            m: 0,
            p: 2,
            borderRadius: 1,
            bgcolor: 'background.default',
            border: '1px solid',
            borderColor: 'divider',
            maxHeight: '60vh',
            overflow: 'auto',
            fontSize: 12,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}
        >
          {lines.length > 0 ? lines.join('\n') : (
            <Typography variant="body2" color="text.secondary">No log output yet.</Typography>
          )}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}
