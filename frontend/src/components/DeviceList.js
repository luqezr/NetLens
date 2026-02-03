import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
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
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import SearchIcon from '@mui/icons-material/Search';
import { getDevices } from '../services/api';

function DeviceList() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  useEffect(() => {
    fetchDevices();
  }, [statusFilter]);

  const fetchDevices = async () => {
    try {
      setLoading(true);
      const params = {};
      if (statusFilter) params.status = statusFilter;
      if (search) params.search = search;

      const response = await getDevices(params);
      setDevices(response.data.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching devices:', error);
      setLoading(false);
    }
  };

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

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          Devices ({filteredDevices.length})
        </Typography>
        <IconButton onClick={fetchDevices} color="primary">
          <RefreshIcon />
        </IconButton>
      </Box>

      <Paper sx={{ p: 2, mb: 2 }}>
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

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>IP Address</TableCell>
              <TableCell>Hostname</TableCell>
              <TableCell>MAC Address</TableCell>
              <TableCell>Vendor</TableCell>
              <TableCell>Device Type</TableCell>
              <TableCell>Connection</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Last Seen</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredDevices
              .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
              .map((device) => (
                <TableRow key={device._id} hover>
                  <TableCell>
                    <Typography variant="body2" fontWeight="bold">
                      {device.ip_address}
                    </Typography>
                  </TableCell>
                  <TableCell>{device.hostname || '-'}</TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {device.mac_address || '-'}
                    </Typography>
                  </TableCell>
                  <TableCell>{device.vendor || '-'}</TableCell>
                  <TableCell>
                    <Chip
                      label={device.device_type || 'Unknown'}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={device.connection?.type || 'Unknown'}
                      size="small"
                      color={getConnectionColor(device.connection?.type)}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={device.status}
                      size="small"
                      color={device.status === 'online' ? 'success' : 'error'}
                    />
                  </TableCell>
                  <TableCell>
                    {new Date(device.last_seen).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
          </TableBody>
        </Table>
        <TablePagination
          rowsPerPageOptions={[10, 25, 50, 100]}
          component="div"
          count={filteredDevices.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </TableContainer>
    </Box>
  );
}

export default DeviceList;
