import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Box, Paper, Typography, Alert, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Button, Divider, TextField, Switch, FormControlLabel, IconButton } from '@mui/material';
import CalendarMonthIcon from '@mui/icons-material/CalendarMonth';
import { Link as RouterLink } from 'react-router-dom';
import { deleteScanSchedule, getScanHistory, getScanSchedule, getScanStatus, getSuggestedNetworkRanges, runScanNow, setScanSchedule, stopAllScans } from '../services/api';
import ScanLiveLogDialog from './ScanLiveLogDialog';
import ExactDateTimeDialog from './ExactDateTimeDialog';
import RunScanDialog from './RunScanDialog';

function formatDate(d) {
  if (!d) return '—';
  try {
    return new Date(d).toLocaleString();
  } catch {
    return String(d);
  }
}

function normalizeTimeTo24h(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;

  // 24h HH:MM
  let m = s.match(/^([01]?\d|2[0-3]):([0-5]\d)$/);
  if (m) {
    const hour = Number(m[1]);
    const minute = Number(m[2]);
    return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
  }

  // 12h h:MM AM/PM
  m = s.match(/^(\d{1,2}):(\d{2})\s*([AaPp][Mm])$/);
  if (m) {
    let hour = Number(m[1]);
    const minute = Number(m[2]);
    const ampm = String(m[3]).toLowerCase();
    if (!Number.isFinite(hour) || hour < 1 || hour > 12) return null;
    if (!Number.isFinite(minute) || minute < 0 || minute > 59) return null;
    if (ampm === 'pm' && hour !== 12) hour += 12;
    if (ampm === 'am' && hour === 12) hour = 0;
    return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
  }

  return null;
}

export default function ScansList() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState(null);
  const [schedule, setSchedule] = useState({ enabled: false, interval_minutes: 60, next_occurrences: [], network_ranges: '' });
  const [scheduleMode, setScheduleMode] = useState('interval');
  const [scheduleDate, setScheduleDate] = useState('');
  const [scheduleTime, setScheduleTime] = useState('');
  const [exactPickerOpen, setExactPickerOpen] = useState(false);
  const [dailyAt, setDailyAt] = useState('03:30');
  const [weeklyAt, setWeeklyAt] = useState('03:30');
  const [weeklyDays, setWeeklyDays] = useState([1, 2, 3, 4, 5]);
  const [scheduleSaving, setScheduleSaving] = useState(false);
  const [forceStopping, setForceStopping] = useState(false);
  const [logOpen, setLogOpen] = useState(false);
  const [runOpen, setRunOpen] = useState(false);
  const [message, setMessage] = useState(null);

  const scheduleDirtyRef = useRef(false);
  const [scheduleDirty, setScheduleDirty] = useState(false);

  const markScheduleDirty = () => {
    scheduleDirtyRef.current = true;
    setScheduleDirty(true);
  };

  const clearScheduleDirty = () => {
    scheduleDirtyRef.current = false;
    setScheduleDirty(false);
  };

  const load = async () => {
    try {
      setError(null);
      setLoading(true);
      // Don't clear success messages on refresh.
      const [historyRes, statusRes, scheduleRes] = await Promise.all([
        getScanHistory({ limit: 100 }),
        getScanStatus(),
        getScanSchedule(),
      ]);

      setItems(historyRes.data.data || []);
      setStatus(statusRes.data.data || null);
      const sched = scheduleRes.data.data || { enabled: false, interval_minutes: 60, next_occurrences: [], network_ranges: '' };

      // Don't clobber unsaved edits during the 5s auto-refresh loop.
      if (!scheduleDirtyRef.current) {
        setSchedule({ ...sched, network_ranges: sched?.network_ranges || '' });

        const mode = ['interval', 'exact', 'daily', 'weekly'].includes(sched?.mode)
          ? sched.mode
          : (sched?.mode === 'exact' ? 'exact' : 'interval');
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
        if (mode === 'daily' && sched?.daily_at) {
          setDailyAt(normalizeTimeTo24h(sched.daily_at) || String(sched.daily_at));
        }
        if (mode === 'weekly') {
          if (sched?.weekly_at) setWeeklyAt(normalizeTimeTo24h(sched.weekly_at) || String(sched.weekly_at));
          if (Array.isArray(sched?.weekly_days) && sched.weekly_days.length > 0) {
            setWeeklyDays(sched.weekly_days.map((n) => Number(n)).filter((n) => Number.isInteger(n) && n >= 0 && n <= 6));
          }
        }
      }
    } catch (e) {
      setError(e?.response?.data?.error || e.message || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  const scheduleFieldSx = (enabled, active) => {
    const main = enabled ? (active ? 'success.main' : undefined) : 'primary.main';
    const label = enabled ? (active ? 'success.main' : undefined) : 'primary.main';
    if (!main && !label) return undefined;
    return {
      '& .MuiInputLabel-root': { color: label },
      '& .MuiOutlinedInput-notchedOutline': { borderColor: main },
      '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: main },
      '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: main },
    };
  };

  const suggestScheduleRangesIfEmpty = async () => {
    try {
      const current = String(schedule?.network_ranges || '').trim();
      if (current) return;
      const res = await getSuggestedNetworkRanges();
      const ranges = res?.data?.data?.ranges || res?.data?.data || res?.data?.ranges || [];
      const first = Array.isArray(ranges) ? ranges[0] : null;
      if (first) {
        markScheduleDirty();
        setSchedule((s) => ({ ...s, network_ranges: String(first) }));
        setMessage({ severity: 'info', text: `Schedule network range set to ${first}. Edit if needed.` });
      }
    } catch {
      // best-effort
    }
  };

  const handleRunScanNow = async ({ networkRanges, verbose } = {}) => {
    try {
      setMessage(null);
      const options = verbose ? { log_level: 'INFO' } : null;
      await runScanNow({
        requested_by: 'ui_scans',
        network_ranges: networkRanges || undefined,
        options,
      });
      setMessage({ severity: 'success', text: 'Scan requested.' });
      setRunOpen(false);
      await load();
    } catch (e) {
      setMessage({ severity: 'error', text: e?.response?.data?.error || e.message || 'Failed to request scan' });
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
    if (!enabled) return [];

    const now = new Date();
    const mode = scheduleMode;

    const parseTimeOfDay = (raw) => {
      const norm = normalizeTimeTo24h(raw);
      if (!norm) return null;
      const m = norm.match(/^(\d{2}):(\d{2})$/);
      return m ? { hour: Number(m[1]), minute: Number(m[2]) } : null;
    };

    const computeNextDaily = (baseNow, timeStr) => {
      const tm = parseTimeOfDay(timeStr);
      if (!tm) return null;
      const d = new Date(baseNow);
      d.setSeconds(0, 0);
      d.setHours(tm.hour, tm.minute, 0, 0);
      if (d.getTime() <= baseNow.getTime()) d.setDate(d.getDate() + 1);
      return d;
    };

    const computeNextWeekly = (baseNow, daysOfWeek, timeStr) => {
      const tm = parseTimeOfDay(timeStr);
      if (!tm) return null;
      const days = Array.isArray(daysOfWeek)
        ? daysOfWeek.map((n) => Number(n)).filter((n) => Number.isInteger(n) && n >= 0 && n <= 6)
        : [];
      const set = new Set(days);
      if (set.size === 0) return null;

      for (let offset = 0; offset <= 8; offset += 1) {
        const d = new Date(baseNow);
        d.setDate(d.getDate() + offset);
        d.setSeconds(0, 0);
        d.setHours(tm.hour, tm.minute, 0, 0);
        if (!set.has(d.getDay())) continue;
        if (d.getTime() <= baseNow.getTime()) continue;
        return d;
      }
      return null;
    };

    if (mode === 'exact') {
      if (!scheduleDate || !scheduleTime) return [];
      const d = new Date(`${scheduleDate}T${scheduleTime}:00`);
      if (Number.isNaN(d.getTime())) return [];
      return [d];
    }

    if (mode === 'daily') {
      const first = computeNextDaily(now, dailyAt);
      if (!first) return [];
      return Array.from({ length: 10 }).map((_, i) => {
        const d = new Date(first);
        d.setDate(d.getDate() + i);
        return d;
      });
    }

    if (mode === 'weekly') {
      const items = [];
      let cursor = new Date(now);
      for (let i = 0; i < 10; i += 1) {
        const next = computeNextWeekly(cursor, weeklyDays, weeklyAt);
        if (!next) break;
        items.push(next);
        cursor = new Date(next.getTime() + 60 * 1000);
      }
      return items;
    }

    // interval
    const interval = Math.max(1, Math.min(1440, Number(schedule?.interval_minutes) || 60));
    let first = null;
    if (status?.next_scheduled_at) {
      const d = new Date(status.next_scheduled_at);
      if (!Number.isNaN(d.getTime())) first = d;
    }
    if (!first) first = new Date(now.getTime() + interval * 60 * 1000);
    return Array.from({ length: 10 }).map((_, i) => new Date(first.getTime() + i * interval * 60 * 1000));
  }, [schedule, scheduleMode, scheduleDate, scheduleTime, dailyAt, weeklyAt, weeklyDays, status]);

  const handleSaveSchedule = async () => {
    try {
      setScheduleSaving(true);
      setError(null);
      setMessage(null);
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

      const dailyAtNorm = scheduleMode === 'daily' ? (normalizeTimeTo24h(dailyAt) || dailyAt) : null;
      const weeklyAtNorm = scheduleMode === 'weekly' ? (normalizeTimeTo24h(weeklyAt) || weeklyAt) : null;

      await setScanSchedule({
        enabled: Boolean(schedule.enabled),
        interval_minutes: Number(schedule.interval_minutes) || 60,
        mode: scheduleMode,
        exact_at: exactAt,
        daily_at: dailyAtNorm,
        weekly_at: weeklyAtNorm,
        weekly_days: scheduleMode === 'weekly' ? weeklyDays : null,
        network_ranges: String(schedule?.network_ranges || '').trim() || null,
      });
      clearScheduleDirty();
      setMessage({ severity: 'success', text: 'Schedule updated.' });
      await load();
    } catch (e) {
      // Keep edits if save failed.
      markScheduleDirty();
      setError(e?.response?.data?.error || e.message || 'Failed to save schedule');
    } finally {
      setScheduleSaving(false);
    }
  };

  const DAYS = [
    { id: 0, label: 'Sun' },
    { id: 1, label: 'Mon' },
    { id: 2, label: 'Tue' },
    { id: 3, label: 'Wed' },
    { id: 4, label: 'Thu' },
    { id: 5, label: 'Fri' },
    { id: 6, label: 'Sat' },
  ];

  const toggleWeeklyDay = (id) => {
    setWeeklyDays((prev) => {
      markScheduleDirty();
      const set = new Set(prev);
      if (set.has(id)) set.delete(id);
      else set.add(id);
      return Array.from(set).sort((a, b) => a - b);
    });
  };

  const handleDisableSchedule = async () => {
    try {
      setScheduleSaving(true);
      await deleteScanSchedule();
      clearScheduleDirty();
      await load();
    } catch (e) {
      setError(e?.response?.data?.error || e.message || 'Failed to disable schedule');
    } finally {
      setScheduleSaving(false);
    }
  };

  // If you are editing schedule fields, the auto-refresh won't clobber them (dirty-state).

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
          <Button color="success" variant="contained" onClick={() => setRunOpen(true)} disabled={loading}>Run Scan Now</Button>
          <Button variant="outlined" onClick={() => setLogOpen(true)} disabled={loading}>Live Log</Button>
          <Button variant="outlined" color="error" onClick={handleForceStop} disabled={loading || forceStopping}>
            Force Stop
          </Button>
          <Button variant="outlined" onClick={load} disabled={loading}>Refresh</Button>
        </Box>
      </Box>

      {message && (
        <Alert severity={message.severity} sx={{ mb: 2 }} onClose={() => setMessage(null)}>
          {message.text}
        </Alert>
      )}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Paper sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Showing the most recent scans (raw details available per scan).
        </Typography>

        <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
          <Typography variant="h6" sx={{ mb: 1 }}>Scheduled</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Next scheduled: {status?.next_scheduled_at ? new Date(status.next_scheduled_at).toLocaleString() : '—'}
            {scheduleDirty ? ' • Editing (auto-refresh paused for schedule controls)' : ''}
          </Typography>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
            <FormControlLabel
              control={(
                <Switch
                  checked={Boolean(schedule.enabled)}
                  onChange={(e) => {
                    const checked = e.target.checked;
                    markScheduleDirty();
                    setSchedule((s) => ({ ...s, enabled: checked }));
                    if (checked) suggestScheduleRangesIfEmpty();
                  }}
                  sx={{
                    '& .MuiSwitch-switchBase': { color: 'primary.main' },
                    '& .MuiSwitch-switchBase + .MuiSwitch-track': { backgroundColor: 'primary.main', opacity: 0.35 },
                    '& .MuiSwitch-switchBase.Mui-checked': { color: 'success.main' },
                    '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { backgroundColor: 'success.main', opacity: 0.45 },
                  }}
                />
              )}
              label="Enable schedule"
            />

            <TextField
              label="Mode"
              size="small"
              select
              SelectProps={{ native: true }}
              value={scheduleMode}
              onChange={(e) => { markScheduleDirty(); setScheduleMode(e.target.value); }}
              sx={{ width: 170, ...(scheduleFieldSx(Boolean(schedule.enabled), true) || {}) }}
            >
              <option value="interval">Interval</option>
              <option value="exact">Exact date/time</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </TextField>

            <TextField
              label="Network range(s)"
              size="small"
              value={schedule.network_ranges || ''}
              onChange={(e) => { markScheduleDirty(); setSchedule((s) => ({ ...s, network_ranges: e.target.value })); }}
              placeholder="e.g. 192.168.50.0/24"
              sx={{ minWidth: 260, ...(scheduleFieldSx(Boolean(schedule.enabled), true) || {}) }}
            />

            <TextField
              label="Interval (minutes)"
              type="number"
              size="small"
              value={schedule.interval_minutes ?? 60}
              onChange={(e) => { markScheduleDirty(); setSchedule((s) => ({ ...s, interval_minutes: e.target.value })); }}
              inputProps={{ min: 1, max: 1440 }}
              sx={{ width: 180, ...(scheduleFieldSx(Boolean(schedule.enabled), scheduleMode === 'interval') || {}) }}
              disabled={scheduleMode !== 'interval'}
            />

            {scheduleMode === 'exact' && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'nowrap' }}>
                  {scheduleDate && scheduleTime ? `${scheduleDate} ${scheduleTime}` : 'Select date/time'}
                </Typography>
                <IconButton
                  size="small"
                  onClick={() => { markScheduleDirty(); setExactPickerOpen(true); }}
                  aria-label="Pick exact date and time"
                  sx={{ color: Boolean(schedule.enabled) ? 'success.main' : 'primary.main' }}
                >
                  <CalendarMonthIcon />
                </IconButton>
              </Box>
            )}

            <TextField
              label="Daily at"
              type="time"
              size="small"
              value={dailyAt}
              onChange={(e) => { markScheduleDirty(); setDailyAt(e.target.value); }}
              sx={{ width: 140, ...(scheduleFieldSx(Boolean(schedule.enabled), scheduleMode === 'daily') || {}) }}
              disabled={scheduleMode !== 'daily'}
              InputLabelProps={{ shrink: true }}
            />

            <TextField
              label="Weekly at"
              type="time"
              size="small"
              value={weeklyAt}
              onChange={(e) => { markScheduleDirty(); setWeeklyAt(e.target.value); }}
              sx={{ width: 140, ...(scheduleFieldSx(Boolean(schedule.enabled), scheduleMode === 'weekly') || {}) }}
              disabled={scheduleMode !== 'weekly'}
              InputLabelProps={{ shrink: true }}
            />

            <Button variant="contained" onClick={handleSaveSchedule} disabled={scheduleSaving}>
              Save
            </Button>
            <Button variant="outlined" onClick={handleDisableSchedule} disabled={scheduleSaving}>
              Disable
            </Button>
          </Box>

          <Typography variant="caption" color="text.secondary" sx={{ mt: 0.75, display: 'block' }}>
            Network range(s): comma-separated CIDRs/IP ranges used for scheduled scans.
          </Typography>

          <ExactDateTimeDialog
            open={exactPickerOpen}
            onClose={() => setExactPickerOpen(false)}
            valueIso={scheduleDate && scheduleTime ? new Date(`${scheduleDate}T${scheduleTime}:00`).toISOString() : null}
            title="Exact schedule"
            onSave={(_iso, parts) => {
              markScheduleDirty();
              if (parts?.date) setScheduleDate(parts.date);
              if (parts?.time) setScheduleTime(parts.time);
            }}
          />

          {scheduleMode === 'weekly' && (
            <Box sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
              <Typography variant="caption" color="text.secondary">Days</Typography>
              {DAYS.map((d) => (
                <Button
                  key={d.id}
                  size="small"
                  variant={weeklyDays.includes(d.id) ? 'contained' : 'outlined'}
                  onClick={() => toggleWeeklyDay(d.id)}
                  color={Boolean(schedule.enabled) ? 'success' : 'primary'}
                >
                  {d.label}
                </Button>
              ))}
            </Box>
          )}

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

      <RunScanDialog
        open={runOpen}
        onClose={() => setRunOpen(false)}
        onRun={async (form) => {
          await handleRunScanNow({ networkRanges: form.networkRanges, verbose: form.verbose });
        }}
      />
    </Box>
  );
}
