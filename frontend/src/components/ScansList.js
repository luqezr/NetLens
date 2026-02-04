import React, { useEffect, useState } from 'react';
import { Box, Paper, Typography, Alert, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Button } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { getScanHistory } from '../services/api';

function formatDate(d) {
  if (!d) return '—';
  try {
    return new Date(d).toLocaleString();
  } catch {
    return String(d);
  }
}

export default function ScansList() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = async () => {
    try {
      setError(null);
      setLoading(true);
      const res = await getScanHistory({ limit: 100 });
      setItems(res.data.data || []);
    } catch (e) {
      setError(e?.response?.data?.error || e.message || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2, gap: 2, flexWrap: 'wrap' }}>
        <Typography variant="h4">Scans</Typography>
        <Button variant="outlined" onClick={load} disabled={loading}>Refresh</Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Paper sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Showing the most recent scans (raw details available per scan).
        </Typography>

        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Started</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Reason</TableCell>
                <TableCell align="right">Hosts</TableCell>
                <TableCell align="right">Duration (s)</TableCell>
                <TableCell align="right">Progress</TableCell>
                <TableCell align="right">Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((s) => {
                const hosts = s?.statistics?.hosts_discovered ?? s?.progress?.total_hosts ?? '—';
                const duration = s?.statistics?.duration_seconds ?? '—';
                const percent = s?.progress?.percent;

                return (
                  <TableRow key={s._id} hover>
                    <TableCell>{formatDate(s.started_at)}</TableCell>
                    <TableCell>{s.status || '—'}</TableCell>
                    <TableCell>{s.reason || '—'}</TableCell>
                    <TableCell align="right">{hosts}</TableCell>
                    <TableCell align="right">{duration}</TableCell>
                    <TableCell align="right">{Number.isFinite(percent) ? `${percent}%` : '—'}</TableCell>
                    <TableCell align="right">
                      <Button component={RouterLink} to={`/scans/${s._id}`} size="small" variant="contained">
                        View
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
              {items.length === 0 && !loading && (
                <TableRow>
                  <TableCell colSpan={7}>No scans yet.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    </Box>
  );
}
