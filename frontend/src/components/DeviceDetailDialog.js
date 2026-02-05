import React, { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { getDeviceByIp } from '../services/api';

function safeToString(value) {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string' && value.trim() === '') return '—';
  return String(value);
}

function formatDate(value) {
  if (!value) return '—';
  try {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return safeToString(value);
    return d.toLocaleString();
  } catch {
    return safeToString(value);
  }
}

function prettyJson(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

function KeyValueTable({ rows }) {
  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableBody>
          {rows
            .filter((r) => r && r.label)
            .map((row) => (
              <TableRow key={row.label}>
                <TableCell sx={{ width: 220, color: 'text.secondary' }}>{row.label}</TableCell>
                <TableCell sx={{ wordBreak: 'break-word' }}>{row.value ?? '—'}</TableCell>
              </TableRow>
            ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

export default function DeviceDetailDialog({ open, onClose, deviceIp, device: deviceProp }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [device, setDevice] = useState(deviceProp || null);

  useEffect(() => {
    setDevice(deviceProp || null);
  }, [deviceProp, open]);

  useEffect(() => {
    const shouldFetch = Boolean(open) && Boolean(deviceIp);
    if (!shouldFetch) return;

    let cancelled = false;
    const load = async () => {
      try {
        setError(null);
        setLoading(true);
        const res = await getDeviceByIp(deviceIp);
        if (cancelled) return;
        setDevice(res.data.data);
      } catch (e) {
        if (cancelled) return;
        setError(e?.response?.data?.error || e.message || 'Failed to load device');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    load();
    return () => {
      cancelled = true;
    };
  }, [open, deviceIp]);

  const title = useMemo(() => {
    const hostname = device?.hostname || (Array.isArray(device?.hostnames) && device.hostnames[0]);
    const ip = device?.ip_address || deviceIp;
    return hostname ? `${hostname} (${ip || '—'})` : (ip || 'Device details');
  }, [device, deviceIp]);

  const services = Array.isArray(device?.services) ? device.services : [];
  const openPortsCount = device?.security?.open_ports_count ?? (Array.isArray(device?.services) ? device.services.length : null);

  const connectionLabel =
    device?.connection_method ||
    device?.connection?.type ||
    device?.connection?.ssid ||
    (typeof device?.connection === 'string' ? device.connection : null);

  const osLabel =
    device?.os?.type ||
    device?.os?.name ||
    device?.os?.family ||
    (typeof device?.os === 'string' ? device.os : null);

  const osVersion = device?.os?.version || device?.os?.os_version || null;

  const raw = device ? prettyJson(device) : '';

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(raw);
    } catch {
      // ignore clipboard errors
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle sx={{ pr: 7 }}>
        {title}
        <Box sx={{ mt: 1, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          {device?.status && (
            <Chip
              label={device.status}
              size="small"
              color={device.status === 'online' ? 'success' : 'default'}
              variant="outlined"
            />
          )}
          {device?.device_type && <Chip label={device.device_type} size="small" variant="outlined" />}
          {device?.vendor && <Chip label={device.vendor} size="small" variant="outlined" />}
          {connectionLabel && <Chip label={`Conn: ${connectionLabel}`} size="small" variant="outlined" />}
          {Number.isFinite(Number(openPortsCount)) && (
            <Chip label={`Open ports: ${openPortsCount}`} size="small" color="warning" variant="outlined" />
          )}
        </Box>
      </DialogTitle>

      <DialogContent dividers>
        {error && <Alert severity="warning" sx={{ mb: 2 }}>{error}</Alert>}

        {loading && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <CircularProgress size={20} />
            <Typography variant="body2" color="text.secondary">Loading device…</Typography>
          </Box>
        )}

        {!device && !loading && (
          <Typography variant="body2" color="text.secondary">No device data available.</Typography>
        )}

        {device && (
          <>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>Summary</Typography>
            <KeyValueTable
              rows={[
                { label: 'IP address', value: <Typography sx={{ fontFamily: 'monospace' }}>{safeToString(device.ip_address || deviceIp)}</Typography> },
                { label: 'Hostname', value: safeToString(device.hostname) },
                { label: 'MAC address', value: <Typography sx={{ fontFamily: 'monospace' }}>{safeToString(device.mac_address)}</Typography> },
                { label: 'Vendor', value: safeToString(device.vendor) },
                { label: 'Device type', value: safeToString(device.device_type) },
                { label: 'OS', value: osLabel ? safeToString(osLabel) : '—' },
                { label: 'OS version', value: osVersion ? safeToString(osVersion) : '—' },
                { label: 'Connection', value: connectionLabel ? safeToString(connectionLabel) : '—' },
                { label: 'First seen', value: formatDate(device.first_seen) },
                { label: 'Last seen', value: formatDate(device.last_seen_on || device.last_seen) },
                { label: 'Last scan', value: formatDate(device.last_scan_on || device.last_scan) },
                { label: 'Uptime (seconds)', value: device.uptime_seconds ?? '—' },
                { label: 'Response time (ms)', value: device.response_time_ms ?? '—' },
                { label: 'Open ports count', value: openPortsCount ?? '—' },
              ]}
            />

            <Divider sx={{ my: 2 }} />

            <Typography variant="subtitle2" sx={{ mb: 1 }}>Services</Typography>
            {services.length === 0 ? (
              <Typography variant="body2" color="text.secondary">No services recorded.</Typography>
            ) : (
              <TableContainer component={Paper} variant="outlined" sx={{ overflowX: 'auto' }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Port</TableCell>
                      <TableCell>Proto</TableCell>
                      <TableCell>State</TableCell>
                      <TableCell>Name</TableCell>
                      <TableCell>Product</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>Reason</TableCell>
                      <TableCell>CPE</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {services.map((s, idx) => (
                      <TableRow key={`${s?.port ?? 'p'}-${s?.protocol ?? 'proto'}-${idx}`} hover>
                        <TableCell sx={{ fontFamily: 'monospace' }}>{safeToString(s?.port)}</TableCell>
                        <TableCell sx={{ fontFamily: 'monospace' }}>{safeToString(s?.protocol)}</TableCell>
                        <TableCell>{safeToString(s?.state)}</TableCell>
                        <TableCell>{safeToString(s?.name)}</TableCell>
                        <TableCell>{safeToString(s?.product)}</TableCell>
                        <TableCell>{safeToString(s?.product_version || s?.version)}</TableCell>
                        <TableCell>{safeToString(s?.reason)}</TableCell>
                        <TableCell>{safeToString(s?.cpe)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}

            <Divider sx={{ my: 2 }} />

            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 2, flexWrap: 'wrap' }}>
              <Typography variant="subtitle2">Raw device JSON</Typography>
              <Button size="small" variant="outlined" startIcon={<ContentCopyIcon />} onClick={handleCopy} disabled={!raw}>
                Copy
              </Button>
            </Box>

            <Box
              component="pre"
              sx={{
                mt: 1,
                p: 2,
                borderRadius: 1,
                bgcolor: 'background.default',
                border: '1px solid',
                borderColor: 'divider',
                maxHeight: '45vh',
                overflow: 'auto',
                fontSize: 12,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
            >
              {raw}
            </Box>
          </>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}
