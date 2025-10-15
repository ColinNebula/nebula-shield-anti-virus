import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals, { reportToAnalytics } from './reportWebVitals';
// Service worker disabled for Electron desktop app
// import * as serviceWorkerRegistration from './serviceWorkerRegistration';
// import toast from 'react-hot-toast';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// Service worker registration disabled for Electron desktop app
// Electron apps don't need service workers since they're native desktop applications
// serviceWorkerRegistration.unregister();

// Report web vitals to analytics
reportToAnalytics();

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
