import React, { useState, useEffect } from 'react';
import { AlertTriangle, Clock, Search, Filter, Tag, Eye, EyeOff, ArrowUp, ArrowDown, Wifi, WifiOff, RefreshCw } from 'lucide-react';
import { useRealTimeData } from '../hooks/useRealTimeData';
import apiClient from '../services/api';
import siemService from '../services/siemIntegration';
import threatIntelService from '../services/threatIntelligence';
import notificationService from '../services/notifications';

interface ProductionAlert {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  timestamp: Date;
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved';
  assignee?: string;
  tags: string[];
  description: string;
  rawData?: any;
  threatIntel?: any;
  sourceIP?: string;
  destinationIP?: string;
  affectedAssets?: string[];
}

interface ProductionAlertsPanelProps {
  isRealTime: boolean;
  fullView?: boolean;
}

const ProductionAlertsPanel: React.FC<ProductionAlertsPanelProps> = ({ isRealTime, fullView = false }) => {
  const [alerts, setAlerts] = useState<ProductionAlert[]>([]);
  const [filteredAlerts, setFilteredAlerts] = useState<ProductionAlert[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'timestamp' | 'severity'>('timestamp');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [isLoading, setIsLoading] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<ProductionAlert | null>(null);

  // Use real-time data hook
  const { 
    data: realTimeAlerts, 
    isConnected, 
    error: connectionError, 
    refresh 
  } = useRealTimeData<ProductionAlert>('alert', [], { enabled: isRealTime });

  // Load initial alerts from API
  useEffect(() => {
    loadAlerts();
  }, []);

  // Update alerts when real-time data changes
  useEffect(() => {
    if (realTimeAlerts.length > 0) {
      setAlerts(prev => {
        const newAlerts = [...realTimeAlerts, ...prev];
        // Remove duplicates based on ID
        const uniqueAlerts = newAlerts.filter((alert, index, self) => 
          index === self.findIndex(a => a.id === alert.id)
        );
        return uniqueAlerts.slice(0, 1000); // Keep latest 1000
      });
    }
  }, [realTimeAlerts]);

  const loadAlerts = async () => {
    setIsLoading(true);
    try {
      const response = await apiClient.getAlerts({ limit: 100 });
      const normalizedAlerts = response.data.map((alert: any) => ({
        ...alert,
        timestamp: new Date(alert.timestamp),
      }));
      setAlerts(normalizedAlerts);
    } catch (error) {
      console.error('Failed to load alerts:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Filter and sort alerts
  useEffect(() => {
    let filtered = alerts.filter(alert => {
      const matchesSearch = alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          alert.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          (alert.sourceIP && alert.sourceIP.includes(searchTerm));
      const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
      const matchesStatus = statusFilter === 'all' || alert.status === statusFilter;
      const matchesSource = sourceFilter === 'all' || alert.source === sourceFilter;
      
      return matchesSearch && matchesSeverity && matchesStatus && matchesSource;
    });

    filtered.sort((a, b) => {
      if (sortBy === 'timestamp') {
        return sortOrder === 'desc' 
          ? b.timestamp.getTime() - a.timestamp.getTime()
          : a.timestamp.getTime() - b.timestamp.getTime();
      } else {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        return sortOrder === 'desc'
          ? severityOrder[b.severity] - severityOrder[a.severity]
          : severityOrder[a.severity] - severityOrder[b.severity];
      }
    });

    setFilteredAlerts(filtered);
  }, [alerts, searchTerm, severityFilter, statusFilter, sourceFilter, sortBy, sortOrder]);

  const handleAlertAction = async (alertId: string, action: string) => {
    try {
      switch (action) {
        case 'acknowledge':
          await apiClient.acknowledgeAlert(alertId, 'current-user-id');
          break;
        case 'investigate':
          await apiClient.updateAlertStatus(alertId, 'investigating');
          break;
        case 'resolve':
          await apiClient.updateAlertStatus(alertId, 'resolved');
          break;
      }
      
      // Update local state
      setAlerts(prev => prev.map(alert => 
        alert.id === alertId 
          ? { ...alert, status: action === 'acknowledge' ? 'acknowledged' : action as any }
          : alert
      ));
    } catch (error) {
      console.error(`Failed to ${action} alert:`, error);
    }
  };

  const enrichWithThreatIntel = async (alert: ProductionAlert) => {
    if (!alert.sourceIP) return;

    try {
      const threatData = await threatIntelService.enrichIOC(alert.sourceIP, 'ip');
      setAlerts(prev => prev.map(a => 
        a.id === alert.id ? { ...a, threatIntel: threatData } : a
      ));
    } catch (error) {
      console.error('Failed to enrich with threat intel:', error);
    }
  };

  const sendNotification = async (alert: ProductionAlert) => {
    try {
      await notificationService.sendNotification({
        title: alert.title,
        message: alert.description,
        severity: alert.severity,
        source: alert.source,
        timestamp: alert.timestamp,
        metadata: {
          alertId: alert.id,
          sourceIP: alert.sourceIP,
          tags: alert.tags,
        },
      });
    } catch (error) {
      console.error('Failed to send notification:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-400/10 border-red-400/20';
      case 'high': return 'text-orange-400 bg-orange-400/10 border-orange-400/20';
      case 'medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
      case 'low': return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
      default: return 'text-slate-400 bg-slate-400/10 border-slate-400/20';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'new': return 'text-red-400 bg-red-400/10';
      case 'acknowledged': return 'text-yellow-400 bg-yellow-400/10';
      case 'investigating': return 'text-blue-400 bg-blue-400/10';
      case 'resolved': return 'text-green-400 bg-green-400/10';
      default: return 'text-slate-400 bg-slate-400/10';
    }
  };

  const uniqueSources = [...new Set(alerts.map(alert => alert.source))];

  return (
    <div className={`bg-slate-800/50 backdrop-blur-sm rounded-xl border border-slate-700/50 ${fullView ? 'p-6' : 'p-4'}`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-5 h-5 text-orange-400" />
          <h3 className="text-lg font-semibold text-white">Production Security Alerts</h3>
          <div className="flex items-center space-x-2">
            {isConnected ? (
              <>
                <Wifi className="w-4 h-4 text-green-400" />
                <span className="text-xs text-green-400">Connected</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4 text-red-400" />
                <span className="text-xs text-red-400">Disconnected</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={refresh}
            disabled={isLoading}
            className="p-2 text-slate-400 hover:text-white transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          <span className="text-sm text-slate-400">{filteredAlerts.length} alerts</span>
        </div>
      </div>

      {connectionError && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
          <p className="text-red-400 text-sm">Connection Error: {connectionError}</p>
        </div>
      )}

      {fullView && (
        <div className="mb-6 space-y-4">
          {/* Search and Filters */}
          <div className="flex flex-col lg:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search alerts, IPs, descriptions..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
            
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Statuses</option>
              <option value="new">New</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>

            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Sources</option>
              {uniqueSources.map(source => (
                <option key={source} value={source}>{source}</option>
              ))}
            </select>

            <button
              onClick={() => {
                setSortBy(sortBy === 'timestamp' ? 'severity' : 'timestamp');
                setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
              }}
              className="flex items-center space-x-2 px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white hover:bg-slate-600/50 transition-colors"
            >
              <span className="text-sm">Sort by {sortBy}</span>
              {sortOrder === 'desc' ? <ArrowDown className="w-4 h-4" /> : <ArrowUp className="w-4 h-4" />}
            </button>
          </div>
        </div>
      )}

      <div className="space-y-3 max-h-96 overflow-y-auto">
        {filteredAlerts.slice(0, fullView ? 100 : 10).map((alert) => (
          <div key={alert.id} className="p-4 bg-slate-700/30 rounded-lg border border-slate-600/30 hover:bg-slate-700/50 transition-colors">
            <div className="flex items-start justify-between mb-2">
              <div className="flex-1">
                <div className="flex items-center space-x-2 mb-1">
                  <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>
                    {alert.severity.toUpperCase()}
                  </span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(alert.status)}`}>
                    {alert.status.replace('_', ' ').toUpperCase()}
                  </span>
                  {alert.threatIntel && (
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                      alert.threatIntel.reputation === 'malicious' ? 'text-red-400 bg-red-400/10' :
                      alert.threatIntel.reputation === 'suspicious' ? 'text-orange-400 bg-orange-400/10' :
                      'text-green-400 bg-green-400/10'
                    }`}>
                      {alert.threatIntel.reputation.toUpperCase()}
                    </span>
                  )}
                </div>
                <h4 className="text-white font-medium">{alert.title}</h4>
                <p className="text-slate-400 text-sm mt-1">{alert.description}</p>
                {alert.sourceIP && (
                  <p className="text-slate-500 text-xs mt-1">Source IP: {alert.sourceIP}</p>
                )}
              </div>
              <div className="text-right text-sm text-slate-400">
                <div>{alert.source}</div>
                <div>{alert.timestamp.toLocaleTimeString()}</div>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                {alert.tags.map((tag) => (
                  <span key={tag} className="px-2 py-1 bg-slate-600/50 text-slate-300 text-xs rounded-md flex items-center">
                    <Tag className="w-3 h-3 mr-1" />
                    {tag}
                  </span>
                ))}
              </div>
              
              <div className="flex items-center space-x-2">
                {alert.status === 'new' && (
                  <button
                    onClick={() => handleAlertAction(alert.id, 'acknowledge')}
                    className="px-2 py-1 text-xs bg-yellow-600/20 text-yellow-400 border border-yellow-600/30 rounded hover:bg-yellow-600/30 transition-colors"
                  >
                    Acknowledge
                  </button>
                )}
                
                {(alert.status === 'new' || alert.status === 'acknowledged') && (
                  <button
                    onClick={() => handleAlertAction(alert.id, 'investigate')}
                    className="px-2 py-1 text-xs bg-blue-600/20 text-blue-400 border border-blue-600/30 rounded hover:bg-blue-600/30 transition-colors"
                  >
                    Investigate
                  </button>
                )}
                
                {alert.sourceIP && !alert.threatIntel && (
                  <button
                    onClick={() => enrichWithThreatIntel(alert)}
                    className="px-2 py-1 text-xs bg-purple-600/20 text-purple-400 border border-purple-600/30 rounded hover:bg-purple-600/30 transition-colors"
                  >
                    Enrich
                  </button>
                )}
                
                <button
                  onClick={() => sendNotification(alert)}
                  className="px-2 py-1 text-xs bg-green-600/20 text-green-400 border border-green-600/30 rounded hover:bg-green-600/30 transition-colors"
                >
                  Notify
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ProductionAlertsPanel;