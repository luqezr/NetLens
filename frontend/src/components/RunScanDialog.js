import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  LinearProgress,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import { getSuggestedNetworkRanges } from '../services/api';

const STORAGE_KEY = 'netlens.runScanForm.v1';

function loadPersisted() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function persist(value) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
  } catch {
    // ignore
  }
}

export default function RunScanDialog({ open, onClose, onRun }) {
  const persisted = useMemo(() => loadPersisted(), []);
  const [networkRanges, setNetworkRanges] = useState(persisted?.networkRanges || '');
  const [verbose, setVerbose] = useState(persisted?.verbose ?? true);
  const [loadingSuggest, setLoadingSuggest] = useState(false);
  const [suggestError, setSuggestError] = useState(null);
  const [suggestions, setSuggestions] = useState([]);

  useEffect(() => {
    if (!open) return;

    // Restore persisted values each time dialog opens (in case user changed them elsewhere).
    const p = loadPersisted();
    if (p?.networkRanges !== undefined) setNetworkRanges(p.networkRanges || '');
    if (p?.verbose !== undefined) setVerbose(Boolean(p.verbose));

    let cancelled = false;
    const loadSuggestions = async () => {
      try {
        setSuggestError(null);
        setLoadingSuggest(true);
        const res = await getSuggestedNetworkRanges();
        if (cancelled) return;
        const list = res?.data?.data?.suggestions || [];
        setSuggestions(list);

        // Auto-fill if empty.
        if (!networkRanges && list.length > 0) {
          setNetworkRanges(list[0].cidr);
        }
      } catch (e) {
        if (cancelled) return;
        setSuggestError(e?.response?.data?.error || e.message || 'Failed to detect network');
      } finally {
        if (!cancelled) setLoadingSuggest(false);
      }
    };

    loadSuggestions();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const handleRun = async () => {
    const next = { networkRanges: networkRanges.trim(), verbose: Boolean(verbose) };
    persist(next);
    await onRun(next);
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Run scan now</DialogTitle>
      <DialogContent>
        {loadingSuggest && <LinearProgress sx={{ mb: 2 }} />}
        {suggestError && <Alert severity="warning" sx={{ mb: 2 }}>{suggestError}</Alert>}

        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Specify one or more network ranges (comma-separated CIDRs). Suggestions are best-effort from the server host network interfaces.
        </Typography>

        <TextField
          label="Network ranges"
          placeholder="192.168.1.0/24, 10.0.0.0/24"
          value={networkRanges}
          onChange={(e) => setNetworkRanges(e.target.value)}
          fullWidth
          sx={{ mb: 2 }}
        />

        {suggestions.length > 0 && (
          <Box sx={{ mb: 2 }}>
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
              Suggested
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              {suggestions.map((s) => (
                <Button
                  key={s.cidr}
                  size="small"
                  variant="outlined"
                  onClick={() => setNetworkRanges(s.cidr)}
                >
                  {s.cidr}
                </Button>
              ))}
            </Box>
          </Box>
        )}

        <FormControlLabel
          control={<Switch checked={verbose} onChange={(e) => setVerbose(e.target.checked)} />}
          label="Verbose (more progress in logs)"
        />

        <Alert severity="info" sx={{ mt: 2 }}>
          This dialog remembers your last values on this browser.
        </Alert>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={handleRun} disabled={!networkRanges.trim()}>
          Run
        </Button>
      </DialogActions>
    </Dialog>
  );
}
