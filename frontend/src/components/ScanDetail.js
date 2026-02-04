import React, { useEffect, useState } from 'react';
import { useParams, Link as RouterLink } from 'react-router-dom';
import { Box, Paper, Typography, Alert, Button } from '@mui/material';
import { getScanHistoryItem } from '../services/api';

function prettyJson(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        setError(null);
        setLoading(true);
        const res = await getScanHistoryItem(id);
        setScan(res.data.data);
      } catch (e) {
        setError(e?.response?.data?.error || e.message || 'Failed to load scan');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2, gap: 2, flexWrap: 'wrap' }}>
        <Typography variant="h4">Scan details</Typography>
        <Button component={RouterLink} to="/scans" variant="outlined">Back to scans</Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Paper sx={{ p: 2 }}>
        {loading && <Typography>Loading…</Typography>}
        {!loading && scan && (
          <>
            <Typography variant="subtitle2" color="text.secondary">
              Started: {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
              {' • '}Status: {scan.status || '—'}
              {' • '}Reason: {scan.reason || '—'}
            </Typography>

            <Box
              component="pre"
              sx={{
                mt: 2,
                p: 2,
                borderRadius: 1,
                bgcolor: 'background.default',
                border: '1px solid',
                borderColor: 'divider',
                maxHeight: '70vh',
                overflow: 'auto',
                fontSize: 12,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
            >
              {prettyJson(scan)}
            </Box>
          </>
        )}
      </Paper>
    </Box>
  );
}
