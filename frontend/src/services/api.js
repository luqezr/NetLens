import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Auth API
export const getMe = () => api.get('/auth/me');
export const login = (data) => api.post('/auth/login', data);
export const logout = () => api.post('/auth/logout');
export const updateProfile = (data) => api.patch('/auth/me', data);
export const changePassword = (data) => api.post('/auth/change-password', data);

// Devices API
export const getDevices = (params) => api.get('/devices', { params });
export const getDeviceByIp = (ip) => api.get(`/devices/${ip}`);
export const updateDevice = (ip, data) => api.patch(`/devices/${ip}`, data);
export const deleteDevice = (ip) => api.delete(`/devices/${ip}`);

// Statistics API
export const getStats = () => api.get('/stats');

// Topology API
export const getTopology = () => api.get('/topology');

// Alerts API
export const getAlerts = (params) => api.get('/alerts', { params });
export const acknowledgeAlert = (id, data) => api.post(`/alerts/${id}/acknowledge`, data);
export const deleteAlert = (id) => api.delete(`/alerts/${id}`);

// Scan control API
export const runScanNow = (data) => api.post('/scans/run', data);
export const getScanSchedule = () => api.get('/scans/schedule');
export const setScanSchedule = (data) => api.post('/scans/schedule', data);
export const getScanStatus = () => api.get('/scans/status');
export const getScanHistory = (params) => api.get('/scans/history', { params });
export const getScanHistoryItem = (id) => api.get(`/scans/history/${id}`);

// Health check
export const healthCheck = () => axios.get('/health');

export default api;
