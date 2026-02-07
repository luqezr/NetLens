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
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DeleteIcon from '@mui/icons-material/Delete';
import { deleteDevice, getDeviceByIp, updateDevice } from '../services/api';

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

export default function DeviceDetailDialog({ open, onClose, onChanged, deviceIp, device: deviceProp }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [device, setDevice] = useState(deviceProp || null);

  const [editType, setEditType] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [saveBusy, setSaveBusy] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [actionError, setActionError] = useState(null);

  useEffect(() => {
    setDevice(deviceProp || null);
  }, [deviceProp, open]);

  useEffect(() => {
    // Initialize edit fields whenever the device changes.
    setEditType(device?.device_type ? String(device.device_type) : '');
    setEditNotes(device?.notes ? String(device.notes) : '');
  }, [device?._id, device?.ip_address, open]);

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

  const cves = Array.isArray(device?.security?.cves) ? device.security.cves : [];
  const cveCountRaw = device?.security?.cve_count;
  const cveCount = Number.isFinite(Number(cveCountRaw)) ? Number(cveCountRaw) : (cves.length || 0);

  const previousIps = Array.isArray(device?.previous_ips) ? device.previous_ips.filter(Boolean) : [];

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

  const deviceTypeOptions = useMemo(
    () => [
      { value: '', label: 'Unknown' },
      { value: 'router', label: 'Router' },
      { value: 'switch', label: 'Switch' },
      { value: 'server', label: 'Server' },
      { value: 'windows_pc', label: 'Windows PC' },
      { value: 'linux_pc', label: 'Linux PC' },
      { value: 'mac', label: 'Mac' },
      { value: 'mobile', label: 'Mobile' },
      { value: 'printer', label: 'Printer' },
      { value: 'network device', label: 'Network device' },
      { value: 'workstation', label: 'Workstation' },
      { value: 'iot', label: 'IoT' },
    ],
    []
  );

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(raw);
    } catch {
      // ignore clipboard errors
    }
  };

  const handleSave = async () => {
    if (!deviceIp && !device?.ip_address) return;
    try {
      setActionError(null);
      setSaveBusy(true);

      const ip = device?.ip_address || deviceIp;
      const payload = {
        device_type: editType === '' ? null : editType,
        notes: editNotes === '' ? null : editNotes,
      };

      const res = await updateDevice(ip, payload);
      const updated = res?.data?.data;
      if (updated) setDevice(updated);

	  try {
		  if (typeof onChanged === 'function') onChanged({ type: 'updated', ip });
	  } catch {
		  // ignore
	  }
    } catch (e) {
      setActionError(e?.response?.data?.error || e.message || 'Failed to update device');
    } finally {
      setSaveBusy(false);
    }
  };

  const handleDelete = async () => {
    if (!deviceIp && !device?.ip_address) return;
    const ip = device?.ip_address || deviceIp;
    const ok = window.confirm(`Delete device ${ip}? This cannot be undone.`);
    if (!ok) return;

    try {
      setActionError(null);
      setDeleteBusy(true);
      await deleteDevice(ip);
      setDevice(null);

	  try {
		  if (typeof onChanged === 'function') onChanged({ type: 'deleted', ip });
	  } catch {
		  // ignore
	  }
      onClose?.();
    } catch (e) {
      setActionError(e?.response?.data?.error || e.message || 'Failed to delete device');
    } finally {
      setDeleteBusy(false);
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
          {Number.isFinite(Number(cveCount)) && cveCount > 0 && (
            <Chip label={`CVEs: ${cveCount}`} size="small" color="error" variant="outlined" />
          )}
        </Box>
      </DialogTitle>

      <DialogContent dividers>
        {error && <Alert severity="warning" sx={{ mb: 2 }}>{error}</Alert>}

        {actionError && <Alert severity="error" sx={{ mb: 2 }}>{actionError}</Alert>}

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
                {
                  label: 'Previously known IPs',
                  value:
                    previousIps.length > 0 ? (
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        {previousIps.map((ip) => (
                          <Chip key={ip} label={ip} size="small" variant="outlined" sx={{ fontFamily: 'monospace' }} />
                        ))}
                      </Box>
                    ) : (
                      '—'
                    ),
                },
                { label: 'Vendor', value: safeToString(device.vendor) },
                {
                  label: 'Device type',
                  value: (
                    <FormControl size="small" sx={{ minWidth: 220 }}>
                      <InputLabel id="device-type-label">Type</InputLabel>
                      <Select
                        labelId="device-type-label"
                        label="Type"
                        value={editType}
                        onChange={(e) => setEditType(e.target.value)}
                        disabled={loading || saveBusy || deleteBusy}
                      >
                        {deviceTypeOptions.map((opt) => (
                          <MenuItem key={opt.value || 'unknown'} value={opt.value}>{opt.label}</MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  ),
                },
                { label: 'OS', value: osLabel ? safeToString(osLabel) : '—' },
                { label: 'OS version', value: osVersion ? safeToString(osVersion) : '—' },
                { label: 'Connection', value: connectionLabel ? safeToString(connectionLabel) : '—' },
                { label: 'First seen', value: formatDate(device.first_seen) },
                { label: 'Last seen', value: formatDate(device.last_seen_on || device.last_seen) },
                { label: 'Last scan', value: formatDate(device.last_scan_on || device.last_scan) },
                { label: 'Uptime (seconds)', value: device.uptime_seconds ?? '—' },
                { label: 'Response time (ms)', value: device.response_time_ms ?? '—' },
                { label: 'Open ports count', value: openPortsCount ?? '—' },
                { label: 'CVE count', value: Number.isFinite(Number(cveCount)) ? cveCount : '—' },
              ]}
            />

            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>Notes</Typography>
              <TextField
                fullWidth
                multiline
                minRows={3}
                placeholder="Add notes about this device…"
                value={editNotes}
                onChange={(e) => setEditNotes(e.target.value)}
                disabled={loading || saveBusy || deleteBusy}
              />
            </Box>

            <Divider sx={{ my: 2 }} />

            <Typography variant="subtitle2" sx={{ mb: 1 }}>Security</Typography>
            {cveCount <= 0 ? (
              <Typography variant="body2" color="text.secondary">No CVEs recorded.</Typography>
            ) : (
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  Detected CVEs from NSE script output (best-effort): {cveCount}
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {cves.slice(0, 200).map((c) => (
                    <Chip
                      key={c}
                      label={c}
                      size="small"
                      color="error"
                      variant="outlined"
                      component="a"
                      href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`}
                      target="_blank"
                      rel="noreferrer"
                      clickable
                    />
                  ))}
                </Box>
                {cves.length > 200 && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                    Showing first 200 CVEs.
                  </Typography>
                )}
              </Box>
            )}

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
        <Button
          color="error"
          variant="outlined"
          startIcon={<DeleteIcon />}
          onClick={handleDelete}
          disabled={!device || loading || saveBusy || deleteBusy}
        >
          Delete device
        </Button>
        <Box sx={{ flex: 1 }} />
        <Button
          onClick={handleSave}
          variant="contained"
          disabled={!device || loading || saveBusy || deleteBusy}
        >
          {saveBusy ? 'Saving…' : 'Save'}
        </Button>
        <Button onClick={onClose} disabled={saveBusy || deleteBusy}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}
