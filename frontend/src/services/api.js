import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

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

// Health check
export const healthCheck = () => axios.get('/health');

export default api;
