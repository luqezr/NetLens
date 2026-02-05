import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import App from './App';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#7c3aed',
    },
    secondary: {
      main: '#22c55e',
    },
    success: {
      main: '#22c55e',
    },
    background: {
      default: '#050508',
      paper: '#0b0b12',
    },
    text: {
      primary: '#ffffff',
      secondary: 'rgba(255,255,255,0.72)',
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        html: {
          height: '100%',
        },
        body: {
          height: '100%',
          scrollbarColor: '#7c3aed #0b0b12',
          scrollbarWidth: 'thin',
        },
        '*': {
          scrollbarColor: '#7c3aed #0b0b12',
          scrollbarWidth: 'thin',
        },
        '*::-webkit-scrollbar': {
          width: '10px',
          height: '10px',
        },
        '*::-webkit-scrollbar-track': {
          backgroundColor: '#0b0b12',
        },
        '*::-webkit-scrollbar-thumb': {
          backgroundColor: '#3b2a78',
          borderRadius: '10px',
          border: '2px solid #0b0b12',
        },
        '*::-webkit-scrollbar-thumb:hover': {
          backgroundColor: '#7c3aed',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: '#0b0b12',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundImage: 'none',
          backgroundColor: '#0b0b12',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
  },
});

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <BrowserRouter>
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <App />
      </ThemeProvider>
    </BrowserRouter>
  </React.StrictMode>
);
