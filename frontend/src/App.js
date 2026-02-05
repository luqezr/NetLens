import React, { useState } from 'react';
import { Routes, Route, Link } from 'react-router-dom';
import { Box, AppBar, Toolbar, Typography, Container, Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, IconButton, Menu, MenuItem, Tooltip, useMediaQuery } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import DashboardIcon from '@mui/icons-material/Dashboard';
import DevicesIcon from '@mui/icons-material/Devices';
import HubIcon from '@mui/icons-material/Hub';
import NotificationsIcon from '@mui/icons-material/Notifications';
import HistoryIcon from '@mui/icons-material/History';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import MenuIcon from '@mui/icons-material/Menu';
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft';
import Dashboard from './components/Dashboard';
import DeviceList from './components/DeviceList';
import NetworkTopology from './components/NetworkTopology';
import AlertsList from './components/AlertsList';
import ScansList from './components/ScansList';
import ScanDetail from './components/ScanDetail';
import Login from './components/Login';
import ProfileDialog from './components/ProfileDialog';
import { AuthProvider, useAuth } from './auth/AuthContext';

const drawerWidth = 240;
const collapsedDrawerWidth = 72;

const menuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { text: 'Devices', icon: <DevicesIcon />, path: '/devices' },
  { text: 'Topology', icon: <HubIcon />, path: '/topology' },
  { text: 'Alerts', icon: <NotificationsIcon />, path: '/alerts' },
  { text: 'Scans', icon: <HistoryIcon />, path: '/scans' },
];

function App() {
  return (
    <AuthProvider>
      <AuthedApp />
    </AuthProvider>
  );
}

function AuthedApp() {
  const { user, loading, logout } = useAuth();
  const [anchorEl, setAnchorEl] = useState(null);
  const [profileOpen, setProfileOpen] = useState(false);
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  if (loading) {
    return <Box sx={{ p: 3 }}><Typography>Loading...</Typography></Box>;
  }

  if (!user) {
    return <Login />;
  }

  const menuOpen = Boolean(anchorEl);
  const effectiveDrawerWidth = sidebarCollapsed ? collapsedDrawerWidth : drawerWidth;

  const drawerContent = (
    <>
      <Toolbar />
      <Box sx={{ overflow: 'auto' }}>
        <List>
          {menuItems.map((item) => (
            <ListItem key={item.text} disablePadding sx={{ display: 'block' }}>
              <Tooltip title={sidebarCollapsed ? item.text : ''} placement="right" disableHoverListener={!sidebarCollapsed}>
                <ListItemButton
                  component={Link}
                  to={item.path}
                  onClick={() => {
                    if (isMobile) setMobileDrawerOpen(false);
                  }}
                  sx={{
                    minHeight: 48,
                    justifyContent: sidebarCollapsed ? 'center' : 'initial',
                    px: 2.5,
                  }}
                >
                  <ListItemIcon
                    sx={{
                      minWidth: 0,
                      mr: sidebarCollapsed ? 'auto' : 2,
                      justifyContent: 'center',
                    }}
                  >
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.text}
                    sx={{
                      opacity: sidebarCollapsed ? 0 : 1,
                      whiteSpace: 'nowrap',
                    }}
                  />
                </ListItemButton>
              </Tooltip>
            </ListItem>
          ))}
        </List>
      </Box>
    </>
  );

  return (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <Toolbar sx={{ display: 'flex', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <IconButton
              color="inherit"
              edge="start"
              onClick={() => {
                if (isMobile) {
                  setMobileDrawerOpen((v) => !v);
                } else {
                  setSidebarCollapsed((v) => !v);
                }
              }}
              sx={{ mr: 1 }}
              aria-label={isMobile ? 'Open navigation menu' : (sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar')}
            >
              {isMobile ? <MenuIcon /> : (sidebarCollapsed ? <MenuIcon /> : <ChevronLeftIcon />)}
            </IconButton>
            <HubIcon sx={{ mr: 2 }} />
            <Typography variant="h6" noWrap component="div">
              NetLens
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="body2" color="text.secondary">{user.username}</Typography>
            <IconButton color="inherit" onClick={(e) => setAnchorEl(e.currentTarget)}>
              <AccountCircleIcon />
            </IconButton>
            <Menu
              anchorEl={anchorEl}
              open={menuOpen}
              onClose={() => setAnchorEl(null)}
              anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
              transformOrigin={{ vertical: 'top', horizontal: 'right' }}
            >
              <MenuItem onClick={() => { setAnchorEl(null); setProfileOpen(true); }}>Profile</MenuItem>
              <MenuItem onClick={async () => { setAnchorEl(null); await logout(); }}>Logout</MenuItem>
            </Menu>
          </Box>
        </Toolbar>
      </AppBar>

      {isMobile ? (
        <Drawer
          variant="temporary"
          open={mobileDrawerOpen}
          onClose={() => setMobileDrawerOpen(false)}
          ModalProps={{ keepMounted: true }}
          sx={{
            display: { xs: 'block', md: 'none' },
            '& .MuiDrawer-paper': { width: drawerWidth, boxSizing: 'border-box' },
          }}
        >
          {drawerContent}
        </Drawer>
      ) : (
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', md: 'block' },
            width: effectiveDrawerWidth,
            flexShrink: 0,
            whiteSpace: 'nowrap',
            '& .MuiDrawer-paper': {
              width: effectiveDrawerWidth,
              boxSizing: 'border-box',
              overflowX: 'hidden',
              transition: theme.transitions.create('width', {
                easing: theme.transitions.easing.sharp,
                duration: theme.transitions.duration.shortest,
              }),
            },
          }}
          open
        >
          {drawerContent}
        </Drawer>
      )}
      
      <Box component="main" sx={{ flexGrow: 1, p: { xs: 2, md: 3 }, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        <Toolbar />
        <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
          <Container maxWidth="xl" sx={{ height: '100%', py: 0 }}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/devices" element={<DeviceList />} />
              <Route path="/topology" element={<NetworkTopology />} />
              <Route path="/alerts" element={<AlertsList />} />
              <Route path="/scans" element={<ScansList />} />
              <Route path="/scans/:id" element={<ScanDetail />} />
            </Routes>
          </Container>
        </Box>
      </Box>

      <ProfileDialog open={profileOpen} onClose={() => setProfileOpen(false)} />
    </Box>
  );
}

export default App;
