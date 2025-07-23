// Environment configuration for production deployment
export const config = {
  // API Configuration
  api: {
    baseUrl: import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001/api',
    timeout: 30000,
    retryAttempts: 3,
  },

  // WebSocket Configuration for Real-time Updates
  websocket: {
    url: import.meta.env.VITE_WS_URL || 'ws://localhost:3001',
    reconnectInterval: 5000,
    maxReconnectAttempts: 10,
  },

  // SIEM Integration Endpoints
  siem: {
    splunk: {
      url: import.meta.env.VITE_SPLUNK_URL,
      token: import.meta.env.VITE_SPLUNK_TOKEN,
    },
    elasticsearch: {
      url: import.meta.env.VITE_ELASTIC_URL,
      apiKey: import.meta.env.VITE_ELASTIC_API_KEY,
    },
    qradar: {
      url: import.meta.env.VITE_QRADAR_URL,
      token: import.meta.env.VITE_QRADAR_TOKEN,
    },
  },

  // Threat Intelligence Feeds
  threatIntel: {
    misp: {
      url: import.meta.env.VITE_MISP_URL,
      apiKey: import.meta.env.VITE_MISP_API_KEY,
    },
    otx: {
      apiKey: import.meta.env.VITE_OTX_API_KEY,
    },
    virustotal: {
      apiKey: import.meta.env.VITE_VT_API_KEY,
    },
  },

  // Notification Integrations
  notifications: {
    slack: {
      webhookUrl: import.meta.env.VITE_SLACK_WEBHOOK,
      channel: import.meta.env.VITE_SLACK_CHANNEL || '#security-alerts',
    },
    teams: {
      webhookUrl: import.meta.env.VITE_TEAMS_WEBHOOK,
    },
    email: {
      smtpHost: import.meta.env.VITE_SMTP_HOST,
      smtpPort: import.meta.env.VITE_SMTP_PORT || 587,
      username: import.meta.env.VITE_SMTP_USER,
      password: import.meta.env.VITE_SMTP_PASS,
    },
  },

  // Security Configuration
  security: {
    jwtSecret: import.meta.env.VITE_JWT_SECRET,
    sessionTimeout: 8 * 60 * 60 * 1000, // 8 hours
    maxLoginAttempts: 5,
    lockoutDuration: 15 * 60 * 1000, // 15 minutes
  },

  // Feature Flags
  features: {
    realTimeAlerts: true,
    threatIntelligence: true,
    automatedResponse: true,
    geoLocation: true,
    mlAnomalyDetection: false, // Enable when ML service is available
  },
};

export default config;