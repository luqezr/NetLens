import React, { useCallback, useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Button,
  Typography,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  IconButton,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TableSortLabel,
  CircularProgress,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import SearchIcon from '@mui/icons-material/Search';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import { getDevices } from '../services/api';
import DeviceDetailDialog from './DeviceDetailDialog';

function formatDate(value) {
  if (!value) return '—';
  try {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return String(value);
    return d.toLocaleString();
  } catch {
    return String(value);
  }
}

function getOsLabel(device) {
  const os = device?.os;
  if (!os) return '—';
  if (typeof os === 'string') return os;
  return os.family || os.name || os.type || '—';
}

function getOsVersionLabel(device) {
  const os = device?.os;
  if (!os || typeof os === 'string') return '—';
  return os.version || os.os_version || '—';
}

function getOpenPortsCount(device) {
  const n = device?.security?.open_ports_count;
  if (Number.isFinite(Number(n))) return Number(n);
  if (Array.isArray(device?.services)) return device.services.length;
  return null;
}

function getCveCount(device) {
  const n = device?.security?.cve_count;
  if (Number.isFinite(Number(n))) return Number(n);
  const list = device?.security?.cves;
  if (Array.isArray(list)) return list.length;
  return 0;
}

function formatPorts(device, max = 4) {
  const services = Array.isArray(device?.services) ? device.services : [];
  const open = services
    .filter((s) => (s?.state ? String(s.state).toLowerCase() === 'open' : true))
    .map((s) => {
      const port = s?.port;
      const proto = s?.protocol;
      if (port === null || port === undefined) return null;
      return proto ? `${port}/${proto}` : String(port);
    })
    .filter(Boolean);

  if (open.length === 0) return '—';
  const shown = open.slice(0, max).join(', ');
  return open.length > max ? `${shown}, …` : shown;
}

function DeviceList() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [detailOpen, setDetailOpen] = useState(false);
  const [selectedDeviceIp, setSelectedDeviceIp] = useState(null);
  const [order, setOrder] = useState('asc');
  const [orderBy, setOrderBy] = useState('device');

  const fetchDevices = useCallback(async () => {
    try {
      setLoading(true);
      const params = {};
      if (statusFilter) params.status = statusFilter;

      const response = await getDevices(params);
      setDevices(response.data.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching devices:', error);
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const getConnectionColor = (type) => {
    switch (type) {
      case 'wired':
        return 'success';
      case 'wireless':
        return 'info';
      default:
        return 'default';
    }
  };

  const filteredDevices = devices.filter((device) =>
    search === '' ||
    device.ip_address.toLowerCase().includes(search.toLowerCase()) ||
    device.hostname?.toLowerCase().includes(search.toLowerCase()) ||
    device.vendor?.toLowerCase().includes(search.toLowerCase())
  );

  const columns = [
    {
      id: 'device',
      label: 'Device',
      type: 'string',
      getValue: (d) => d?.hostname || d?.ip_address || '',
      render: (device) => (
        <>
          <Button
            variant="text"
            onClick={() => openDeviceDetails(device)}
            sx={{
              textTransform: 'none',
              px: 0,
              justifyContent: 'flex-start',
              minWidth: 0,
              fontWeight: 700,
              whiteSpace: 'nowrap',
            }}
          >
            {device.hostname || device.ip_address}
          </Button>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            {device.connection_method || device.connection?.type || (typeof device.connection === 'string' ? device.connection : 'Unknown')}
          </Typography>
        </>
      ),
    },
    {
      id: 'ip_address',
      label: 'IP Address',
      type: 'string',
      getValue: (d) => d?.ip_address || '',
      render: (device) => (
        <Typography variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
          {device.ip_address || '-'}
        </Typography>
      ),
    },
    {
      id: 'mac_address',
      label: 'MAC',
      type: 'string',
      getValue: (d) => d?.mac_address || '',
      render: (device) => (
        <Typography variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
          {device.mac_address || '-'}
        </Typography>
      ),
    },
    {
      id: 'vendor',
      label: 'Vendor',
      type: 'string',
      getValue: (d) => d?.vendor || '',
      render: (device) => (
        <Typography
          variant="body2"
          noWrap
          title={device.vendor || ''}
          sx={{
            maxWidth: { xs: 140, sm: 180, md: 240, lg: 320, xl: 420 },
          }}
        >
          {device.vendor || '-'}
        </Typography>
      ),
    },
    {
      id: 'device_type',
      label: 'Type',
      type: 'string',
      getValue: (d) => d?.device_type || '',
      render: (device) => (
        <Chip label={device.device_type || 'Unknown'} size="small" variant="outlined" sx={{ whiteSpace: 'nowrap' }} />
      ),
    },
    {
      id: 'connection',
      label: 'Connection',
      type: 'string',
      getValue: (d) => d?.connection_method || d?.connection?.type || (typeof d?.connection === 'string' ? d.connection : ''),
      render: (device) => (
        <Chip
          label={device.connection_method || device.connection?.type || (typeof device.connection === 'string' ? device.connection : 'Unknown')}
          size="small"
          color={getConnectionColor(device.connection_method || device.connection?.type || (typeof device.connection === 'string' ? device.connection : undefined))}
          variant="outlined"
          sx={{ whiteSpace: 'nowrap' }}
        />
      ),
    },
    {
      id: 'os',
      label: 'OS',
      type: 'string',
      getValue: (d) => getOsLabel(d),
      render: (device) => (
        <Typography
          variant="body2"
          noWrap
          title={getOsLabel(device)}
          sx={{
            maxWidth: { xs: 140, sm: 180, md: 220, lg: 260, xl: 340 },
          }}
        >
          {getOsLabel(device)}
        </Typography>
      ),
    },
    {
      id: 'os_version',
      label: 'OS Version',
      type: 'string',
      getValue: (d) => getOsVersionLabel(d),
      render: (device) => getOsVersionLabel(device),
    },
    {
      id: 'ports',
      label: 'Ports',
      type: 'string',
      getValue: (d) => formatPorts(d, 999),
      render: (device) => (
        <Typography variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
          {formatPorts(device)}
        </Typography>
      ),
    },
    {
      id: 'open_ports_count',
      label: 'Open',
      type: 'number',
      align: 'right',
      getValue: (d) => getOpenPortsCount(d),
      render: (device) => (getOpenPortsCount(device) ?? '—'),
    },
    {
      id: 'vulnerabilities',
      label: 'Vulnerabilities',
      type: 'number',
      align: 'center',
      getValue: (d) => getCveCount(d),
      render: (device) => {
        const n = getCveCount(device);
        return n > 0 ? (
          <CancelIcon sx={{ color: 'error.main' }} titleAccess={`${n} CVE(s) found`} />
        ) : (
          <CheckCircleIcon sx={{ color: 'success.main' }} titleAccess="No CVEs found" />
        );
      },
    },
    {
      id: 'status',
      label: 'Status',
      type: 'string',
      getValue: (d) => d?.status || '',
      render: (device) => (
        <Chip
          label={device.status}
          size="small"
          color={device.status === 'online' ? 'success' : 'error'}
          sx={{ whiteSpace: 'nowrap' }}
        />
      ),
    },
    {
      id: 'first_seen',
      label: 'First Seen',
      type: 'date',
      getValue: (d) => d?.first_seen,
      render: (device) => formatDate(device.first_seen),
    },
    {
      id: 'last_seen',
      label: 'Last Seen',
      type: 'date',
      getValue: (d) => d?.last_seen_on || d?.last_seen,
      render: (device) => formatDate(device.last_seen_on || device.last_seen),
    },
    {
      id: 'last_scan',
      label: 'Last Scan',
      type: 'date',
      getValue: (d) => d?.last_scan_on || d?.last_scan,
      render: (device) => formatDate(device.last_scan_on || device.last_scan),
    },
  ];

  function normalizeSortValue(value, type) {
    if (type === 'number') {
      const n = Number(value);
      return Number.isFinite(n) ? n : -Infinity;
    }
    if (type === 'date') {
      const t = new Date(value).getTime();
      return Number.isFinite(t) ? t : 0;
    }
    if (value === null || value === undefined) return '';
    return String(value).toLowerCase();
  }

  function getComparator(orderDirection, sortKey) {
    const col = columns.find((c) => c.id === sortKey) || columns[0];
    const dir = orderDirection === 'desc' ? -1 : 1;
    return (a, b) => {
      const av = normalizeSortValue(col.getValue(a), col.type);
      const bv = normalizeSortValue(col.getValue(b), col.type);
      if (av < bv) return -1 * dir;
      if (av > bv) return 1 * dir;
      return 0;
    };
  }

  function stableSort(array, comparator) {
    const stabilized = array.map((el, index) => [el, index]);
    stabilized.sort((a, b) => {
      const orderCmp = comparator(a[0], b[0]);
      if (orderCmp !== 0) return orderCmp;
      return a[1] - b[1];
    });
    return stabilized.map((el) => el[0]);
  }

  const sortedDevices = stableSort(filteredDevices, getComparator(order, orderBy));

  const handleRequestSort = (property) => {
    const isAsc = orderBy === property && order === 'asc';
    setOrder(isAsc ? 'desc' : 'asc');
    setOrderBy(property);
    setPage(0);
  };

  const openDeviceDetails = (device) => {
    const ip = device?.ip_address;
    if (!ip) return;
    setSelectedDeviceIp(ip);
    setDetailOpen(true);
  };

  return (
    <Box sx={{ height: '100%', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flex: '0 0 auto' }}>
        <Typography variant="h4">
          Devices ({filteredDevices.length})
        </Typography>
        <IconButton onClick={fetchDevices} color="primary" disabled={loading}>
          <RefreshIcon />
        </IconButton>
      </Box>

      <Paper sx={{ p: 2, mb: 2, flex: '0 0 auto' }}>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <TextField
            placeholder="Search IP, hostname, vendor..."
            variant="outlined"
            size="small"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            InputProps={{
              startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
            }}
            sx={{ flexGrow: 1 }}
          />
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Status</InputLabel>
            <Select
              value={statusFilter}
              label="Status"
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="online">Online</MenuItem>
              <MenuItem value="offline">Offline</MenuItem>
            </Select>
          </FormControl>
        </Box>
      </Paper>

      <Paper sx={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        <TableContainer sx={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
          <Table size="small" stickyHeader sx={{ width: '100%', tableLayout: 'auto' }}>
            <TableHead>
              <TableRow>
                {columns.map((col) => (
                  <TableCell
                    key={col.id}
                    align={col.align || 'left'}
                    sortDirection={orderBy === col.id ? order : false}
                    sx={{ whiteSpace: 'nowrap' }}
                  >
                    <TableSortLabel
                      active={orderBy === col.id}
                      direction={orderBy === col.id ? order : 'asc'}
                      onClick={() => handleRequestSort(col.id)}
                    >
                      {col.label}
                    </TableSortLabel>
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {loading && (
                <TableRow>
                  <TableCell colSpan={columns.length}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      <CircularProgress size={18} />
                      <Typography variant="body2" color="text.secondary">Loading devices…</Typography>
                    </Box>
                  </TableCell>
                </TableRow>
              )}

              {!loading && sortedDevices
                .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                .map((device) => (
                  <TableRow key={device._id} hover>
                    {columns.map((col) => (
                      <TableCell key={col.id} align={col.align || 'left'} sx={{ whiteSpace: 'nowrap', verticalAlign: 'top' }}>
                        {col.render(device)}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}

              {!loading && filteredDevices.length === 0 && (
                <TableRow>
                  <TableCell colSpan={columns.length}>
                    <Typography variant="body2" color="text.secondary">No devices found.</Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>

        <TablePagination
          rowsPerPageOptions={[10, 25, 50, 100]}
          component="div"
          count={filteredDevices.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
          sx={{ flex: '0 0 auto' }}
        />
      </Paper>

      <DeviceDetailDialog
        open={detailOpen}
        onClose={() => setDetailOpen(false)}
        deviceIp={selectedDeviceIp}
      />
    </Box>
  );
}

export default DeviceList;
