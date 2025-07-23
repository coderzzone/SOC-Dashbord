import axios, { AxiosInstance, AxiosResponse } from 'axios';
import config from '../config/environment';

// API Client with authentication and error handling
class ApiClient {
  private client: AxiosInstance;
  private token: string | null = null;

  constructor() {
    this.client = axios.create({
      baseURL: config.api.baseUrl,
      timeout: config.api.timeout,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor for authentication
    this.client.interceptors.request.use(
      (config) => {
        if (this.token) {
          config.headers.Authorization = `Bearer ${this.token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401) {
          this.clearToken();
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('auth_token', token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('auth_token');
  }

  // Authentication endpoints
  async login(credentials: { email: string; password: string }) {
    const response = await this.client.post('/auth/login', credentials);
    if (response.data.token) {
      this.setToken(response.data.token);
    }
    return response.data;
  }

  async logout() {
    try {
      await this.client.post('/auth/logout');
    } finally {
      this.clearToken();
    }
  }

  // Alert management
  async getAlerts(filters?: {
    severity?: string;
    status?: string;
    source?: string;
    limit?: number;
    offset?: number;
  }) {
    const response = await this.client.get('/alerts', { params: filters });
    return response.data;
  }

  async updateAlertStatus(alertId: string, status: string) {
    const response = await this.client.patch(`/alerts/${alertId}`, { status });
    return response.data;
  }

  async acknowledgeAlert(alertId: string, userId: string) {
    const response = await this.client.post(`/alerts/${alertId}/acknowledge`, { userId });
    return response.data;
  }

  // Incident management
  async getIncidents(filters?: {
    status?: string;
    severity?: string;
    assignee?: string;
  }) {
    const response = await this.client.get('/incidents', { params: filters });
    return response.data;
  }

  async createIncident(incident: {
    title: string;
    description: string;
    severity: string;
    alertIds?: string[];
  }) {
    const response = await this.client.post('/incidents', incident);
    return response.data;
  }

  async updateIncident(incidentId: string, updates: any) {
    const response = await this.client.patch(`/incidents/${incidentId}`, updates);
    return response.data;
  }

  // Case management
  async getCases(filters?: {
    status?: string;
    priority?: string;
    assignee?: string;
  }) {
    const response = await this.client.get('/cases', { params: filters });
    return response.data;
  }

  async createCase(caseData: {
    title: string;
    description: string;
    priority: string;
    assignee?: string;
    relatedIncidents?: string[];
  }) {
    const response = await this.client.post('/cases', caseData);
    return response.data;
  }

  // Log queries
  async queryLogs(query: {
    searchTerm?: string;
    timeRange?: { start: Date; end: Date };
    sources?: string[];
    severity?: string[];
    limit?: number;
  }) {
    const response = await this.client.post('/logs/query', query);
    return response.data;
  }

  // Threat intelligence
  async enrichIOC(ioc: string, type: 'ip' | 'domain' | 'hash' | 'url') {
    const response = await this.client.post('/threat-intel/enrich', { ioc, type });
    return response.data;
  }

  // User management (Admin only)
  async getUsers() {
    const response = await this.client.get('/users');
    return response.data;
  }

  async createUser(userData: {
    name: string;
    email: string;
    role: string;
    department: string;
  }) {
    const response = await this.client.post('/users', userData);
    return response.data;
  }

  async updateUser(userId: string, updates: any) {
    const response = await this.client.patch(`/users/${userId}`, updates);
    return response.data;
  }

  // KPI and metrics
  async getKPIMetrics(timeRange?: { start: Date; end: Date }) {
    const response = await this.client.get('/metrics/kpi', { params: timeRange });
    return response.data;
  }

  async getAlertMetrics(timeRange?: { start: Date; end: Date }) {
    const response = await this.client.get('/metrics/alerts', { params: timeRange });
    return response.data;
  }
}

export const apiClient = new ApiClient();
export default apiClient;