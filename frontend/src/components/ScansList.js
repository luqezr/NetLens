import React, { useEffect, useMemo, useState } from 'react';
import { Box, Paper, Typography, Alert, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Button, Divider, TextField, Switch, FormControlLabel } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { deleteScanSchedule, getScanHistory, getScanSchedule, getScanStatus, setScanSchedule, stopAllScans } from '../services/api';
import ScanLiveLogDialog from './ScanLiveLogDialog';

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
  const [status, setStatus] = useState(null);
  const [schedule, setSchedule] = useState({ enabled: false, interval_minutes: 60, next_occurrences: [] });
  const [scheduleMode, setScheduleMode] = useState('interval');
  const [scheduleDate, setScheduleDate] = useState('');
  const [scheduleTime, setScheduleTime] = useState('');
  const [scheduleSaving, setScheduleSaving] = useState(false);
  const [forceStopping, setForceStopping] = useState(false);
  const [logOpen, setLogOpen] = useState(false);

  const load = async () => {
    try {
      setError(null);
      setLoading(true);
      const [historyRes, statusRes, scheduleRes] = await Promise.all([
        getScanHistory({ limit: 100 }),
        getScanStatus(),
        getScanSchedule(),
      ]);

      setItems(historyRes.data.data || []);
      setStatus(statusRes.data.data || null);
      const sched = scheduleRes.data.data || { enabled: false, interval_minutes: 60, next_occurrences: [] };
      setSchedule(sched);

      const mode = sched?.mode === 'exact' ? 'exact' : 'interval';
      setScheduleMode(mode);
      if (mode === 'exact' && sched?.exact_at) {
        const d = new Date(sched.exact_at);
        if (!Number.isNaN(d.getTime())) {
          // Convert to local date/time strings for inputs.
          const yyyy = d.getFullYear();
          const mm = String(d.getMonth() + 1).padStart(2, '0');
          const dd = String(d.getDate()).padStart(2, '0');
          const hh = String(d.getHours()).padStart(2, '0');
          const mi = String(d.getMinutes()).padStart(2, '0');
          setScheduleDate(`${yyyy}-${mm}-${dd}`);
          setScheduleTime(`${hh}:${mi}`);
        }
      }
    } catch (e) {
      setError(e?.response?.data?.error || e.message || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    // Keep progress live.
    const interval = setInterval(() => {
      load();
    }, 5000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const nextOccurrences = useMemo(() => {
    const enabled = Boolean(schedule?.enabled);
    const interval = Math.max(1, Math.min(1440, Number(schedule?.interval_minutes) || 60));
    const existing = Array.isArray(schedule?.next_occurrences) ? schedule.next_occurrences : [];
    if (enabled && existing.length > 0) return existing;

    if (!enabled) return [];
    const now = new Date();
    const first = new Date(now.getTime() + interval * 60 * 1000);
    return Array.from({ length: 10 }).map((_, i) => new Date(first.getTime() + i * interval * 60 * 1000));
  }, [schedule]);

  const handleSaveSchedule = async () => {
    try {
      setScheduleSaving(true);
      let exactAt = null;
      if (scheduleMode === 'exact') {
        if (!scheduleDate || !scheduleTime) {
          throw new Error('Please select both a date and time for the exact schedule.');
        }
        // Interpret date/time as local time.
        const local = new Date(`${scheduleDate}T${scheduleTime}:00`);
        if (Number.isNaN(local.getTime())) {
          throw new Error('Invalid date/time');
        }
        exactAt = local.toISOString();
      }

      await setScanSchedule({
        enabled: Boolean(schedule.enabled),
        interval_minutes: Number(schedule.interval_minutes) || 60,
        mode: scheduleMode,
        exact_at: exactAt,
      });
      await load();
    } catch (e) {
      setError(e?.response?.data?.error || e.message || 'Failed to save schedule');
    } finally {
      setScheduleSaving(false);
    }
  };

  const handleDisableSchedule = async () => {
    try {
      setScheduleSaving(true);
      await deleteScanSchedule();
      await load();
    } catch (e) {
      setError(e?.response?.data?.error || e.message || 'Failed to disable schedule');
    } finally {
      setScheduleSaving(false);
    }
  };

  const handleForceStop = async () => {
    const ok = window.confirm('Force stop all scans? This will terminate the running scanner process and cancel queued requests.');
    if (!ok) return;
    try {
      setForceStopping(true);
      await stopAllScans({ requested_by: 'ui' });
      await load();
    } catch (e) {
      setError(e?.response?.data?.error || e.message || 'Failed to force stop scans');
    } finally {
      setForceStopping(false);
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2, gap: 2, flexWrap: 'wrap' }}>
        <Typography variant="h4">Scans</Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Button variant="outlined" onClick={() => setLogOpen(true)} disabled={loading}>Live Log</Button>
          <Button variant="outlined" color="error" onClick={handleForceStop} disabled={loading || forceStopping}>
            Force Stop
          </Button>
          <Button variant="outlined" onClick={load} disabled={loading}>Refresh</Button>
        </Box>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Paper sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Showing the most recent scans (raw details available per scan).
        </Typography>

        <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
          <Typography variant="h6" sx={{ mb: 1 }}>Scheduled</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Next scheduled: {status?.next_scheduled_at ? new Date(status.next_scheduled_at).toLocaleString() : '—'}
          </Typography>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
            <FormControlLabel
              control={<Switch checked={Boolean(schedule.enabled)} onChange={(e) => setSchedule((s) => ({ ...s, enabled: e.target.checked }))} />}
              label="Enable schedule"
            />

            <TextField
              label="Mode"
              size="small"
              select
              SelectProps={{ native: true }}
              value={scheduleMode}
              onChange={(e) => setScheduleMode(e.target.value)}
              sx={{ width: 170 }}
            >
              <option value="interval">Interval</option>
              <option value="exact">Exact date/time</option>
            </TextField>

            <TextField
              label="Interval (minutes)"
              type="number"
              size="small"
              value={schedule.interval_minutes ?? 60}
              onChange={(e) => setSchedule((s) => ({ ...s, interval_minutes: e.target.value }))}
              inputProps={{ min: 1, max: 1440 }}
              sx={{ width: 180 }}
              disabled={scheduleMode !== 'interval'}
            />

            <TextField
              label="Date"
              type="date"
              size="small"
              value={scheduleDate}
              onChange={(e) => setScheduleDate(e.target.value)}
              sx={{ width: 180 }}
              disabled={scheduleMode !== 'exact'}
              InputLabelProps={{ shrink: true }}
            />

            <TextField
              label="Time"
              type="time"
              size="small"
              value={scheduleTime}
              onChange={(e) => setScheduleTime(e.target.value)}
              sx={{ width: 140 }}
              disabled={scheduleMode !== 'exact'}
              InputLabelProps={{ shrink: true }}
            />

            <Button variant="contained" onClick={handleSaveSchedule} disabled={scheduleSaving}>
              Save
            </Button>
            <Button variant="outlined" onClick={handleDisableSchedule} disabled={scheduleSaving}>
              Disable
            </Button>
          </Box>

          {Boolean(schedule.enabled) && nextOccurrences.length > 0 && (
            <Box sx={{ mt: 2 }}>
              <Divider sx={{ mb: 1 }} />
              <Typography variant="subtitle2" sx={{ mb: 1 }}>Next 10 occurrences</Typography>
              <Box component="ul" sx={{ m: 0, pl: 2, color: 'text.secondary' }}>
                {nextOccurrences.slice(0, 10).map((d, idx) => (
                  <li key={idx}>{formatDate(d)}</li>
                ))}
              </Box>
            </Box>
          )}
        </Paper>

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
                <TableCell align="right">Live Log</TableCell>
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
                    <TableCell align="right">
                      <Button size="small" variant="outlined" onClick={() => setLogOpen(true)}>
                        Live
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
              {items.length === 0 && !loading && (
                <TableRow>
                  <TableCell colSpan={8}>No scans yet.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      <ScanLiveLogDialog open={logOpen} onClose={() => setLogOpen(false)} />
    </Box>
  );
}
