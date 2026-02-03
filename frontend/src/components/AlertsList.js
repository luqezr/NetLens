import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  IconButton,
  Chip,
  List,
  ListItem,
  ListItemText,
  Button,
  Divider,
  ToggleButton,
  ToggleButtonGroup,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import CheckIcon from '@mui/icons-material/Check';
import DeleteIcon from '@mui/icons-material/Delete';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import { getAlerts, acknowledgeAlert, deleteAlert } from '../services/api';

const severityIcons = {
  low: <InfoIcon />,
  medium: <WarningIcon />,
  high: <ErrorIcon />,
  critical: <ErrorIcon />,
};

const severityColors = {
  low: 'info',
  medium: 'warning',
  high: 'error',
  critical: 'error',
};

function AlertsList() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    fetchAlerts();
  }, [filter]);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const params = {};
      if (filter === 'unacknowledged') params.acknowledged = false;
      if (filter === 'acknowledged') params.acknowledged = true;

      const response = await getAlerts(params);
      setAlerts(response.data.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching alerts:', error);
      setLoading(false);
    }
  };

  const handleAcknowledge = async (alertId) => {
    try {
      await acknowledgeAlert(alertId, { acknowledged_by: 'admin' });
      fetchAlerts();
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    }
  };

  const handleDelete = async (alertId) => {
    try {
      await deleteAlert(alertId);
      fetchAlerts();
    } catch (error) {
      console.error('Error deleting alert:', error);
    }
  };

  const unacknowledgedCount = alerts.filter((a) => !a.acknowledged).length;

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4">
            Alerts
          </Typography>
          <Chip
            label={`${unacknowledgedCount} Unacknowledged`}
            color="error"
            size="small"
            sx={{ mt: 1 }}
          />
        </Box>
        <IconButton onClick={fetchAlerts} color="primary">
          <RefreshIcon />
        </IconButton>
      </Box>

      <Paper sx={{ p: 2, mb: 2 }}>
        <ToggleButtonGroup
          value={filter}
          exclusive
          onChange={(e, newFilter) => newFilter && setFilter(newFilter)}
          aria-label="alert filter"
        >
          <ToggleButton value="all" aria-label="all alerts">
            All
          </ToggleButton>
          <ToggleButton value="unacknowledged" aria-label="unacknowledged alerts">
            Unacknowledged
          </ToggleButton>
          <ToggleButton value="acknowledged" aria-label="acknowledged alerts">
            Acknowledged
          </ToggleButton>
        </ToggleButtonGroup>
      </Paper>

      <Paper>
        <List>
          {alerts.length === 0 ? (
            <ListItem>
              <ListItemText primary="No alerts found" />
            </ListItem>
          ) : (
            alerts.map((alert, index) => (
              <React.Fragment key={alert._id}>
                <ListItem
                  secondaryAction={
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      {!alert.acknowledged && (
                        <IconButton
                          edge="end"
                          aria-label="acknowledge"
                          onClick={() => handleAcknowledge(alert._id)}
                          color="primary"
                        >
                          <CheckIcon />
                        </IconButton>
                      )}
                      <IconButton
                        edge="end"
                        aria-label="delete"
                        onClick={() => handleDelete(alert._id)}
                        color="error"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Box>
                  }
                  sx={{
                    bgcolor: alert.acknowledged ? 'transparent' : 'rgba(255, 0, 0, 0.05)',
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', width: '100%', gap: 2 }}>
                    <Box sx={{ mt: 1 }}>
                      <Chip
                        icon={severityIcons[alert.severity]}
                        label={alert.severity}
                        color={severityColors[alert.severity]}
                        size="small"
                      />
                    </Box>
                    <Box sx={{ flexGrow: 1 }}>
                      <Typography variant="subtitle1" fontWeight="bold">
                        {alert.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                        {alert.message}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 2, mt: 1 }}>
                        {alert.device_id && (
                          <Typography variant="caption" color="text.secondary">
                            Device: {alert.device_id.hostname || alert.device_id.ip_address}
                          </Typography>
                        )}
                        <Typography variant="caption" color="text.secondary">
                          {new Date(alert.created_at).toLocaleString()}
                        </Typography>
                        {alert.acknowledged && (
                          <Chip
                            label={`Acked by ${alert.acknowledged_by}`}
                            size="small"
                            variant="outlined"
                          />
                        )}
                      </Box>
                    </Box>
                  </Box>
                </ListItem>
                {index < alerts.length - 1 && <Divider />}
              </React.Fragment>
            ))
          )}
        </List>
      </Paper>
    </Box>
  );
}

export default AlertsList;
