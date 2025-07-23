import config from '../config/environment';
import apiClient from './api';

// SIEM Integration Service for connecting to various security platforms
class SIEMIntegrationService {
  
  // Splunk Integration
  async querySplunk(searchQuery: string, timeRange?: { earliest: string; latest: string }) {
    try {
      const response = await fetch(`${config.siem.splunk.url}/services/search/jobs`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${config.siem.splunk.token}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          search: searchQuery,
          earliest_time: timeRange?.earliest || '-24h',
          latest_time: timeRange?.latest || 'now',
          output_mode: 'json',
        }),
      });
      
      return await response.json();
    } catch (error) {
      console.error('Splunk query failed:', error);
      throw error;
    }
  }

  // Elasticsearch Integration
  async queryElasticsearch(query: any, index: string = 'security-*') {
    try {
      const response = await fetch(`${config.siem.elasticsearch.url}/${index}/_search`, {
        method: 'POST',
        headers: {
          'Authorization': `ApiKey ${config.siem.elasticsearch.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(query),
      });
      
      return await response.json();
    } catch (error) {
      console.error('Elasticsearch query failed:', error);
      throw error;
    }
  }

  // QRadar Integration
  async queryQRadar(aql: string) {
    try {
      const response = await fetch(`${config.siem.qradar.url}/api/ariel/searches`, {
        method: 'POST',
        headers: {
          'SEC': config.siem.qradar.token,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query_expression: aql,
        }),
      });
      
      return await response.json();
    } catch (error) {
      console.error('QRadar query failed:', error);
      throw error;
    }
  }

  // Generic log query that routes to appropriate SIEM
  async queryLogs(params: {
    query: string;
    timeRange?: { start: Date; end: Date };
    source?: 'splunk' | 'elasticsearch' | 'qradar';
    limit?: number;
  }) {
    const { query, timeRange, source = 'elasticsearch', limit = 100 } = params;

    switch (source) {
      case 'splunk':
        return this.querySplunk(query, {
          earliest: timeRange?.start.toISOString() || '-24h',
          latest: timeRange?.end.toISOString() || 'now',
        });
      
      case 'elasticsearch':
        return this.queryElasticsearch({
          query: {
            bool: {
              must: [
                { query_string: { query } },
                ...(timeRange ? [{
                  range: {
                    '@timestamp': {
                      gte: timeRange.start.toISOString(),
                      lte: timeRange.end.toISOString(),
                    }
                  }
                }] : [])
              ]
            }
          },
          size: limit,
          sort: [{ '@timestamp': { order: 'desc' } }]
        });
      
      case 'qradar':
        return this.queryQRadar(query);
      
      default:
        throw new Error(`Unsupported SIEM source: ${source}`);
    }
  }

  // Real-time alert streaming
  async streamAlerts(callback: (alert: any) => void) {
    // This would typically connect to SIEM's streaming API
    // For now, we'll use our WebSocket service
    const wsService = await import('./websocket');
    wsService.default.subscribe('alert', callback);
  }

  // Parse and normalize alerts from different SIEMs
  normalizeAlert(rawAlert: any, source: string) {
    const baseAlert = {
      id: '',
      title: '',
      description: '',
      severity: 'medium',
      source: source,
      timestamp: new Date(),
      status: 'new',
      tags: [],
      details: {},
    };

    switch (source) {
      case 'splunk':
        return {
          ...baseAlert,
          id: rawAlert._cd || rawAlert.id,
          title: rawAlert.signature || rawAlert.title,
          description: rawAlert.message || rawAlert.description,
          severity: this.mapSplunkSeverity(rawAlert.severity),
          timestamp: new Date(rawAlert._time * 1000),
          details: rawAlert,
        };

      case 'elasticsearch':
        return {
          ...baseAlert,
          id: rawAlert._id,
          title: rawAlert._source.rule?.name || rawAlert._source.message,
          description: rawAlert._source.message,
          severity: this.mapElasticSeverity(rawAlert._source.severity),
          timestamp: new Date(rawAlert._source['@timestamp']),
          details: rawAlert._source,
        };

      case 'qradar':
        return {
          ...baseAlert,
          id: rawAlert.id?.toString(),
          title: rawAlert.offense_type || 'QRadar Alert',
          description: rawAlert.description,
          severity: this.mapQRadarSeverity(rawAlert.severity),
          timestamp: new Date(rawAlert.start_time),
          details: rawAlert,
        };

      default:
        return { ...baseAlert, details: rawAlert };
    }
  }

  private mapSplunkSeverity(severity: string): string {
    const mapping: { [key: string]: string } = {
      'critical': 'critical',
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'info': 'info',
    };
    return mapping[severity?.toLowerCase()] || 'medium';
  }

  private mapElasticSeverity(severity: number | string): string {
    if (typeof severity === 'number') {
      if (severity >= 8) return 'critical';
      if (severity >= 6) return 'high';
      if (severity >= 4) return 'medium';
      if (severity >= 2) return 'low';
      return 'info';
    }
    return severity?.toString().toLowerCase() || 'medium';
  }

  private mapQRadarSeverity(severity: number): string {
    if (severity >= 8) return 'critical';
    if (severity >= 6) return 'high';
    if (severity >= 4) return 'medium';
    if (severity >= 2) return 'low';
    return 'info';
  }
}

export const siemService = new SIEMIntegrationService();
export default siemService;