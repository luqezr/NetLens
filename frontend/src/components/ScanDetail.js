import React, { useEffect, useState } from 'react';
import { useParams, Link as RouterLink } from 'react-router-dom';
import { Box, Paper, Typography, Alert, Button, Chip, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Divider } from '@mui/material';
import { getScanHistoryItem } from '../services/api';
import DeviceDetailDialog from './DeviceDetailDialog';

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
  const [deviceDetailOpen, setDeviceDetailOpen] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);

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

            <Box sx={{ mt: 1, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              {scan?.network_ranges && <Chip label={`Range: ${scan.network_ranges}`} size="small" variant="outlined" />}
              {scan?.environment?.wifi_ssid && <Chip label={`SSID: ${scan.environment.wifi_ssid}`} size="small" variant="outlined" />}
              {Number.isFinite(Number(scan?.progress?.percent)) && <Chip label={`Progress: ${scan.progress.percent}%`} size="small" color="primary" variant="outlined" />}
              {Number.isFinite(Number(scan?.progress?.total_hosts)) && <Chip label={`Hosts: ${scan.progress.total_hosts}`} size="small" variant="outlined" />}
              {Number.isFinite(Number(scan?.statistics?.duration_seconds)) && <Chip label={`Duration: ${scan.statistics.duration_seconds}s`} size="small" variant="outlined" />}
            </Box>

            {Array.isArray(scan?.devices) && scan.devices.length > 0 && (
              <>
                <Divider sx={{ my: 2 }} />
                <Typography variant="h6" sx={{ mb: 1 }}>Devices ({scan.devices.length})</Typography>

                <TableContainer component={Paper} variant="outlined" sx={{ overflowX: 'auto' }}>
                  <Table size="small" stickyHeader sx={{ minWidth: 900 }}>
                    <TableHead>
                      <TableRow>
                        <TableCell>Device</TableCell>
                        <TableCell>IP</TableCell>
                        <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>MAC</TableCell>
                        <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>OS</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>Type</TableCell>
                        <TableCell align="right">Open Ports</TableCell>
                        <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>First Seen</TableCell>
                        <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>Last Seen</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {scan.devices.map((d, idx) => {
                        const hostname = d?.hostname || (Array.isArray(d?.hostnames) ? d.hostnames[0] : null);
                        const openPorts = d?.security?.open_ports_count ?? (Array.isArray(d?.services) ? d.services.length : '—');
                        const osLabel = d?.os?.family || d?.os?.name || d?.os?.type || (typeof d?.os === 'string' ? d.os : null);

                        return (
                          <TableRow
                            key={`${d?.ip_address || 'ip'}-${idx}`}
                            hover
                            sx={{ cursor: 'pointer' }}
                            onClick={() => {
                              setSelectedDevice(d);
                              setDeviceDetailOpen(true);
                            }}
                          >
                            <TableCell sx={{ fontWeight: 700 }}>{hostname || d?.ip_address || '—'}</TableCell>
                            <TableCell sx={{ fontFamily: 'monospace' }}>{d?.ip_address || '—'}</TableCell>
                            <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' }, fontFamily: 'monospace' }}>{d?.mac_address || '—'}</TableCell>
                            <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>{osLabel || '—'}</TableCell>
                            <TableCell>
                              <Chip
                                label={d?.status || '—'}
                                size="small"
                                color={d?.status === 'online' ? 'success' : 'default'}
                                variant="outlined"
                              />
                            </TableCell>
                            <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>{d?.device_type || '—'}</TableCell>
                            <TableCell align="right">{openPorts}</TableCell>
                            <TableCell sx={{ display: { xs: 'none', lg: 'table-cell' } }}>{d?.first_seen ? new Date(d.first_seen).toLocaleString() : '—'}</TableCell>
                            <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>{d?.last_seen_on ? new Date(d.last_seen_on).toLocaleString() : (d?.last_seen ? new Date(d.last_seen).toLocaleString() : '—')}</TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </TableContainer>
              </>
            )}

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

      <DeviceDetailDialog
        open={deviceDetailOpen}
        onClose={() => setDeviceDetailOpen(false)}
        device={selectedDevice}
        deviceIp={selectedDevice?.ip_address}
      />
    </Box>
  );
}
