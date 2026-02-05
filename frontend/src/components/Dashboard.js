import React, { useState, useEffect } from 'react';
import { Grid, Paper, Typography, Box, Card, CardContent, Button, TextField, Switch, FormControlLabel, Alert, Snackbar, LinearProgress } from '@mui/material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import DevicesIcon from '@mui/icons-material/Devices';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import WarningIcon from '@mui/icons-material/Warning';
import { getStats, runScanNow, getScanSchedule, setScanSchedule, getScanStatus } from '../services/api';
import RunScanDialog from './RunScanDialog';

const COLORS = ['#7c3aed', '#22c55e', '#a855f7', '#10b981', '#c084fc'];

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanSchedule, setScanScheduleState] = useState({ enabled: true, interval_minutes: 60 });
  const [scanStatus, setScanStatus] = useState(null);
  const [scanActionLoading, setScanActionLoading] = useState(false);
  const [scanScheduleSaving, setScanScheduleSaving] = useState(false);
  const [scanMessage, setScanMessage] = useState(null);
  const [scanToastDismissed, setScanToastDismissed] = useState(false);
  const [runDialogOpen, setRunDialogOpen] = useState(false);

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
      setScanScheduleState(scheduleRes.data.data);
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
      await setScanSchedule({
        enabled: Boolean(scanSchedule.enabled),
        interval_minutes: Number(scanSchedule.interval_minutes) || 60,
      });
      setScanMessage({ severity: 'success', text: 'Schedule updated.' });
      await fetchScanControls();
    } catch (error) {
      setScanMessage({ severity: 'error', text: error?.response?.data?.error || error.message || 'Failed to update schedule' });
    } finally {
      setScanScheduleSaving(false);
    }
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
                      onChange={(e) => setScanScheduleState((s) => ({ ...s, enabled: e.target.checked }))}
                    />
                  }
                  label="Enable schedule"
                />

                <TextField
                  label="Interval (minutes)"
                  type="number"
                  size="small"
                  value={scanSchedule.interval_minutes ?? 60}
                  onChange={(e) => setScanScheduleState((s) => ({ ...s, interval_minutes: e.target.value }))}
                  inputProps={{ min: 1, max: 1440 }}
                  sx={{ width: 170 }}
                />

                <Button variant="outlined" onClick={handleSaveSchedule} disabled={scanScheduleSaving}>
                  Save Schedule
                </Button>
              </Box>
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
