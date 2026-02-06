import React, { useRef, useState, useEffect } from 'react';
import { Grid, Paper, Typography, Box, Card, CardContent, Button, TextField, Switch, FormControlLabel, Alert, Snackbar, LinearProgress, IconButton } from '@mui/material';
import CalendarMonthIcon from '@mui/icons-material/CalendarMonth';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import DevicesIcon from '@mui/icons-material/Devices';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import WarningIcon from '@mui/icons-material/Warning';
import { getStats, runScanNow, getScanSchedule, setScanSchedule, getScanStatus, getSuggestedNetworkRanges } from '../services/api';
import RunScanDialog from './RunScanDialog';
import ExactDateTimeDialog from './ExactDateTimeDialog';

const COLORS = ['#7c3aed', '#22c55e', '#a855f7', '#10b981', '#c084fc'];

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

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanSchedule, setScanScheduleState] = useState({ enabled: true, interval_minutes: 60, network_ranges: '' });
  const [scheduleMode, setScheduleMode] = useState('interval');
  const [scheduleDate, setScheduleDate] = useState('');
  const [scheduleTime, setScheduleTime] = useState('');
  const [exactPickerOpen, setExactPickerOpen] = useState(false);
  const [dailyAt, setDailyAt] = useState('03:30');
  const [weeklyAt, setWeeklyAt] = useState('03:30');
  const [weeklyDays, setWeeklyDays] = useState([1, 2, 3, 4, 5]);
  const [scanStatus, setScanStatus] = useState(null);
  const [scanActionLoading, setScanActionLoading] = useState(false);
  const [scanScheduleSaving, setScanScheduleSaving] = useState(false);
  const [scanMessage, setScanMessage] = useState(null);
  const [scanToastDismissed, setScanToastDismissed] = useState(false);
  const [runDialogOpen, setRunDialogOpen] = useState(false);

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
      const current = String(scanSchedule?.network_ranges || '').trim();
      if (current) return;
      const res = await getSuggestedNetworkRanges();
      const ranges = res?.data?.data?.ranges || res?.data?.data || res?.data?.ranges || [];
      const first = Array.isArray(ranges) ? ranges[0] : null;
      if (first) {
        markScheduleDirty();
        setScanScheduleState((s) => ({ ...s, network_ranges: String(first) }));
        setScanMessage({ severity: 'info', text: `Schedule network range set to ${first}. Edit if needed.` });
      }
    } catch {
      // best-effort
    }
  };

  useEffect(() => {
    fetchStats();
    fetchScanControls();
    const interval = setInterval(fetchStats, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Poll scan status more frequently so the UI shows progress.
    const interval = setInterval(() => {
      fetchScanControls();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const runningCount = Number(scanStatus?.running_requests ?? 0);
    const queuedCount = Number(scanStatus?.pending_requests ?? scanStatus?.queued_requests ?? 0);
    const isActive = Boolean(scanStatus?.running) || runningCount > 0 || queuedCount > 0;

    if (!isActive && scanToastDismissed) {
      setScanToastDismissed(false);
    }
  }, [scanStatus, scanToastDismissed]);

  const fetchStats = async () => {
    try {
      const response = await getStats();
      setStats(response.data.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching stats:', error);
      setLoading(false);
    }
  };

  const fetchScanControls = async () => {
    try {
      const [scheduleRes, statusRes] = await Promise.all([getScanSchedule(), getScanStatus()]);
      const sched = scheduleRes.data.data;

      // Don't clobber unsaved edits during polling.
      if (!scheduleDirtyRef.current) {
        setScanScheduleState({ ...sched, network_ranges: sched?.network_ranges || '' });

        const mode = ['interval', 'exact', 'daily', 'weekly'].includes(sched?.mode)
          ? sched.mode
          : (sched?.mode === 'exact' ? 'exact' : 'interval');
        setScheduleMode(mode);
        if (mode === 'exact' && sched?.exact_at) {
          const d = new Date(sched.exact_at);
          if (!Number.isNaN(d.getTime())) {
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
      setScanStatus(statusRes.data.data);
    } catch (error) {
      console.error('Error fetching scan controls:', error);
    }
  };

  const handleRunScanNow = async ({ networkRanges, verbose } = {}) => {
    try {
      setScanActionLoading(true);
      setScanMessage(null);
      const options = verbose
        ? {
            // Increase log verbosity from the scanner service.
            log_level: 'INFO',
          }
        : null;

      await runScanNow({
        requested_by: 'ui',
        network_ranges: networkRanges || undefined,
        options,
      });
      setScanMessage({ severity: 'success', text: 'Scan requested.' });
      await fetchScanControls();
    } catch (error) {
      setScanMessage({ severity: 'error', text: error?.response?.data?.error || error.message || 'Failed to request scan' });
    } finally {
      setScanActionLoading(false);
    }
  };

  const handleSaveSchedule = async () => {
    try {
      setScanScheduleSaving(true);
      setScanMessage(null);

      let exactAt = null;
      if (scheduleMode === 'exact') {
        if (!scheduleDate || !scheduleTime) {
          throw new Error('Please select both a date and time for the exact schedule.');
        }
        const local = new Date(`${scheduleDate}T${scheduleTime}:00`);
        if (Number.isNaN(local.getTime())) {
          throw new Error('Invalid date/time');
        }
        exactAt = local.toISOString();
      }

      await setScanSchedule({
        enabled: Boolean(scanSchedule.enabled),
        interval_minutes: Number(scanSchedule.interval_minutes) || 60,
        mode: scheduleMode,
        exact_at: exactAt,
        daily_at: scheduleMode === 'daily' ? (normalizeTimeTo24h(dailyAt) || dailyAt) : null,
        weekly_at: scheduleMode === 'weekly' ? (normalizeTimeTo24h(weeklyAt) || weeklyAt) : null,
        weekly_days: scheduleMode === 'weekly' ? weeklyDays : null,
        network_ranges: String(scanSchedule?.network_ranges || '').trim() || null,
      });
      setScanMessage({ severity: 'success', text: 'Schedule updated.' });

      clearScheduleDirty();
      await fetchScanControls();
    } catch (error) {
      // Restore dirty state if save failed so polling doesn't clobber the form.
      markScheduleDirty();
      setScanMessage({ severity: 'error', text: error?.response?.data?.error || error.message || 'Failed to update schedule' });
    } finally {
      setScanScheduleSaving(false);
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

  if (loading) {
    return <Typography>Loading...</Typography>;
  }

  const deviceTypeData = stats?.by_type?.map(item => ({
    name: item._id || 'Unknown',
    value: item.count
  })) || [];

  const vendorData = stats?.by_vendor?.slice(0, 10) || [];

  const runningCount = Number(scanStatus?.running_requests ?? 0);
  const queuedCount = Number(scanStatus?.pending_requests ?? scanStatus?.queued_requests ?? 0);
  const isActive = Boolean(scanStatus?.running) || runningCount > 0 || queuedCount > 0;
  const percent = Number(scanStatus?.current_request?.progress_percent);
  const hasPercent = Number.isFinite(percent) && percent >= 0 && percent <= 100;
  const scanError = scanStatus?.current_request?.error || null;
  const scanReason = scanStatus?.current_request?.reason || '';
  const scanEnvironment = scanStatus?.current_request?.environment || {};
  
  // Get network ranges from environment or config
  const networkRanges = process.env.REACT_APP_NETWORK_RANGES || scanStatus?.current_request?.network_ranges || 'Not specified';

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Network Overview
      </Typography>

      {scanMessage && (
        <Box sx={{ mb: 2 }}>
          <Alert severity={scanMessage.severity} onClose={() => setScanMessage(null)}>
            {scanMessage.text}
          </Alert>
        </Box>
      )}

      {/* Scan Controls */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
              <Box>
                <Typography variant="h6">Scan Controls</Typography>
                <Typography variant="body2" color="text.secondary">
                  Last scan: {scanStatus?.latest_scan?.started_at ? new Date(scanStatus.latest_scan.started_at).toLocaleString() : '—'}
                  {' • '}Queued: {scanStatus?.pending_requests ?? scanStatus?.queued_requests ?? '—'}
                  {' • '}Running: {scanStatus?.running_requests ?? '—'}
                  {scheduleDirty ? ' • Editing schedule' : ''}
                </Typography>
              </Box>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
                <Button variant="contained" onClick={() => setRunDialogOpen(true)} disabled={scanActionLoading}>
                  Run Scan Now
                </Button>

                <FormControlLabel
                  control={
                    <Switch
                      checked={Boolean(scanSchedule.enabled)}
                      onChange={(e) => {
                        const checked = e.target.checked;
                        markScheduleDirty();
                        setScanScheduleState((s) => ({ ...s, enabled: checked }));
                        if (checked) suggestScheduleRangesIfEmpty();
                      }}
                      sx={{
                        '& .MuiSwitch-switchBase': { color: 'primary.main' },
                        '& .MuiSwitch-switchBase + .MuiSwitch-track': { backgroundColor: 'primary.main', opacity: 0.35 },
                        '& .MuiSwitch-switchBase.Mui-checked': { color: 'success.main' },
                        '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { backgroundColor: 'success.main', opacity: 0.45 },
                      }}
                    />
                  }
                  label="Enable schedule"
                />

                <TextField
                  label="Mode"
                  size="small"
                  select
                  SelectProps={{ native: true }}
                  value={scheduleMode}
                  onChange={(e) => {
                    markScheduleDirty();
                    setScheduleMode(e.target.value);
                  }}
                  sx={{ width: 150, ...(scheduleFieldSx(Boolean(scanSchedule.enabled), true) || {}) }}
                >
                  <option value="interval">Interval</option>
                  <option value="exact">Exact date/time</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                </TextField>

                <TextField
                  label="Network range(s)"
                  size="small"
                  value={scanSchedule.network_ranges || ''}
                  onChange={(e) => {
                    markScheduleDirty();
                    setScanScheduleState((s) => ({ ...s, network_ranges: e.target.value }));
                  }}
                  placeholder="e.g. 192.168.50.0/24"
                  sx={{ minWidth: 260, ...(scheduleFieldSx(Boolean(scanSchedule.enabled), true) || {}) }}
                />

                <TextField
                  label="Interval (minutes)"
                  type="number"
                  size="small"
                  value={scanSchedule.interval_minutes ?? 60}
                  onChange={(e) => {
                    markScheduleDirty();
                    setScanScheduleState((s) => ({ ...s, interval_minutes: e.target.value }));
                  }}
                  inputProps={{ min: 1, max: 1440 }}
                  sx={{ width: 170, ...(scheduleFieldSx(Boolean(scanSchedule.enabled), scheduleMode === 'interval') || {}) }}
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
                      sx={{ color: Boolean(scanSchedule.enabled) ? 'success.main' : 'primary.main' }}
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
                  onChange={(e) => {
                    markScheduleDirty();
                    setDailyAt(e.target.value);
                  }}
                  sx={{ width: 130, ...(scheduleFieldSx(Boolean(scanSchedule.enabled), scheduleMode === 'daily') || {}) }}
                  disabled={scheduleMode !== 'daily'}
                  InputLabelProps={{ shrink: true }}
                />

                <TextField
                  label="Weekly at"
                  type="time"
                  size="small"
                  value={weeklyAt}
                  onChange={(e) => {
                    markScheduleDirty();
                    setWeeklyAt(e.target.value);
                  }}
                  sx={{ width: 130, ...(scheduleFieldSx(Boolean(scanSchedule.enabled), scheduleMode === 'weekly') || {}) }}
                  disabled={scheduleMode !== 'weekly'}
                  InputLabelProps={{ shrink: true }}
                />

                <Button variant="outlined" onClick={handleSaveSchedule} disabled={scanScheduleSaving}>
                  Save Schedule
                </Button>
              </Box>

              <Typography variant="caption" color="text.secondary" sx={{ mt: 0.75, display: 'block' }}>
                Network range(s): comma-separated CIDRs/IP ranges used for scheduled scans.
              </Typography>

              {scheduleMode === 'weekly' && (
                <Box sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                  <Typography variant="caption" color="text.secondary">Days</Typography>
                  {DAYS.map((d) => (
                    <Button
                      key={d.id}
                      size="small"
                      variant={weeklyDays.includes(d.id) ? 'contained' : 'outlined'}
                      onClick={() => toggleWeeklyDay(d.id)}
                      color={Boolean(scanSchedule.enabled) ? 'success' : 'primary'}
                    >
                      {d.label}
                    </Button>
                  ))}
                </Box>
              )}
            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* Scan toast */}
      <Snackbar
        open={isActive && !scanToastDismissed}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        onClose={() => setScanToastDismissed(true)}
        message={null}
      >
        <Paper sx={{ p: 2, minWidth: 320, maxWidth: 450, border: '1px solid', borderColor: scanError ? 'error.main' : 'divider' }}>
          <Typography variant="subtitle1" sx={{ color: scanError ? 'error.main' : 'inherit' }}>
            {scanError ? 'Scan Error' : `Scanning${hasPercent ? ` (${percent}%)` : ''}`}
          </Typography>
          {scanError && (
            <Typography variant="body2" color="error" sx={{ mb: 1 }}>
              {scanError}
            </Typography>
          )}
          {!scanError && (
            <>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                Running: {runningCount} • Queued: {queuedCount}
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
                Network: {networkRanges}
              </Typography>
            </>
          )}
          <LinearProgress 
            variant={hasPercent ? 'determinate' : 'indeterminate'} 
            value={hasPercent ? percent : undefined}
            color={scanError ? 'error' : 'primary'}
          />
        </Paper>
      </Snackbar>

      <RunScanDialog
        open={runDialogOpen}
        onClose={() => setRunDialogOpen(false)}
        onRun={async (form) => {
          await handleRunScanNow({ networkRanges: form.networkRanges, verbose: form.verbose });
          setRunDialogOpen(false);
        }}
      />

      <ExactDateTimeDialog
        open={exactPickerOpen}
        onClose={() => setExactPickerOpen(false)}
        valueIso={scheduleDate && scheduleTime ? new Date(`${scheduleDate}T${scheduleTime}:00`).toISOString() : null}
        title="Exact schedule"
        onSave={(_iso, parts) => {
          if (parts?.date) setScheduleDate(parts.date);
          if (parts?.time) setScheduleTime(parts.time);
        }}
      />

      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #4c1d95 0%, #7c3aed 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="white" variant="h3">
                    {stats?.total_devices || 0}
                  </Typography>
                  <Typography color="white" variant="body2">
                    Total Devices
                  </Typography>
                </Box>
                <DevicesIcon sx={{ fontSize: 48, color: 'rgba(255,255,255,0.3)' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #14532d 0%, #22c55e 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="white" variant="h3">
                    {stats?.online_devices || 0}
                  </Typography>
                  <Typography color="white" variant="body2">
                    Online Devices
                  </Typography>
                </Box>
                <CheckCircleIcon sx={{ fontSize: 48, color: 'rgba(255,255,255,0.3)' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #111827 0%, #ef4444 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="white" variant="h3">
                    {stats?.offline_devices || 0}
                  </Typography>
                  <Typography color="white" variant="body2">
                    Offline Devices
                  </Typography>
                </Box>
                <CancelIcon sx={{ fontSize: 48, color: 'rgba(255,255,255,0.3)' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #312e81 0%, #a855f7 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="white" variant="h3">
                    {deviceTypeData.length}
                  </Typography>
                  <Typography color="white" variant="body2">
                    Device Types
                  </Typography>
                </Box>
                <WarningIcon sx={{ fontSize: 48, color: 'rgba(255,255,255,0.3)' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Devices by Type
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={deviceTypeData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {deviceTypeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Top Vendors
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={vendorData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="_id" angle={-45} textAnchor="end" height={100} />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="count" fill="#7c3aed" name="Devices" />
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Recently Seen Devices
            </Typography>
            <Box sx={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                    <th style={{ padding: '12px', textAlign: 'left' }}>IP Address</th>
                    <th style={{ padding: '12px', textAlign: 'left' }}>Hostname</th>
                    <th style={{ padding: '12px', textAlign: 'left' }}>Type</th>
                    <th style={{ padding: '12px', textAlign: 'left' }}>Status</th>
                    <th style={{ padding: '12px', textAlign: 'left' }}>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {stats?.recent_devices?.map((device) => (
                    <tr key={device.ip_address} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <td style={{ padding: '12px' }}>{device.ip_address}</td>
                      <td style={{ padding: '12px' }}>{device.hostname || '-'}</td>
                      <td style={{ padding: '12px' }}>{device.device_type || 'Unknown'}</td>
                      <td style={{ padding: '12px' }}>
                        <Box
                          sx={{
                            display: 'inline-block',
                            px: 2,
                            py: 0.5,
                            borderRadius: 1,
                            bgcolor: device.status === 'online' ? 'success.main' : 'error.main',
                          }}
                        >
                          {device.status}
                        </Box>
                      </td>
                      <td style={{ padding: '12px' }}>
                        {new Date(device.last_seen).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard;
