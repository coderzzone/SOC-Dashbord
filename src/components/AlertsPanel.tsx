import React, { useState, useEffect } from 'react';
import { AlertTriangle, Clock, Search, Filter, Tag, Eye, EyeOff, ArrowUp, ArrowDown } from 'lucide-react';

interface Alert {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  timestamp: Date;
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved';
  assignee?: string;
  tags: string[];
  description: string;
}

interface AlertsPanelProps {
  isRealTime: boolean;
  fullView?: boolean;
}

const AlertsPanel: React.FC<AlertsPanelProps> = ({ isRealTime, fullView = false }) => {
  const [alerts, setAlerts] = useState<Alert[]>([
    {
      id: '1',
      title: 'Suspicious Login Activity Detected',
      severity: 'critical',
      source: 'Authentication System',
      timestamp: new Date(Date.now() - 300000),
      status: 'new',
      tags: ['authentication', 'brute-force'],
      description: 'Multiple failed login attempts from IP 192.168.1.100'
    },
    {
      id: '2',
      title: 'Malware Signature Detected',
      severity: 'high',
      source: 'Antivirus Engine',
      timestamp: new Date(Date.now() - 600000),
      status: 'investigating',
      assignee: 'John Doe',
      tags: ['malware', 'endpoint'],
      description: 'Trojan.Generic detected on workstation WS-001'
    },
    {
      id: '3',
      title: 'Unusual Network Traffic',
      severity: 'medium',
      source: 'Network Monitor',
      timestamp: new Date(Date.now() - 900000),
      status: 'acknowledged',
      tags: ['network', 'anomaly'],
      description: 'High bandwidth usage detected from internal host'
    }
  ]);

  const [filteredAlerts, setFilteredAlerts] = useState(alerts);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'timestamp' | 'severity'>('timestamp');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  // Simulate real-time alerts
  useEffect(() => {
    if (!isRealTime) return;

    const interval = setInterval(() => {
      if (Math.random() > 0.8) {
        const newAlert: Alert = {
          id: Date.now().toString(),
          title: getRandomAlertTitle(),
          severity: getRandomSeverity(),
          source: getRandomSource(),
          timestamp: new Date(),
          status: 'new',
          tags: getRandomTags(),
          description: 'New security event detected requiring investigation'
        };
        setAlerts(prev => [newAlert, ...prev].slice(0, 50));
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [isRealTime]);

  // Filter and sort alerts
  useEffect(() => {
    let filtered = alerts.filter(alert => {
      const matchesSearch = alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          alert.description.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
      const matchesStatus = statusFilter === 'all' || alert.status === statusFilter;
      
      return matchesSearch && matchesSeverity && matchesStatus;
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
  }, [alerts, searchTerm, severityFilter, statusFilter, sortBy, sortOrder]);

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

  const getRandomAlertTitle = () => {
    const titles = [
      'Suspicious Network Activity',
      'Failed Authentication Attempt',
      'Malware Detection Alert',
      'Unauthorized Access Attempt',
      'Data Exfiltration Detected',
      'Phishing Email Detected',
      'Privilege Escalation Attempt'
    ];
    return titles[Math.floor(Math.random() * titles.length)];
  };

  const getRandomSeverity = (): Alert['severity'] => {
    const severities: Alert['severity'][] = ['critical', 'high', 'medium', 'low'];
    return severities[Math.floor(Math.random() * severities.length)];
  };

  const getRandomSource = () => {
    const sources = ['Firewall', 'IDS', 'Antivirus', 'SIEM', 'Network Monitor', 'Endpoint Protection'];
    return sources[Math.floor(Math.random() * sources.length)];
  };

  const getRandomTags = () => {
    const allTags = ['malware', 'network', 'authentication', 'data-loss', 'phishing', 'endpoint'];
    return allTags.slice(0, Math.floor(Math.random() * 3) + 1);
  };

  return (
    <div className={`bg-slate-800/50 backdrop-blur-sm rounded-xl border border-slate-700/50 ${fullView ? 'p-6' : 'p-4'}`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-5 h-5 text-orange-400" />
          <h3 className="text-lg font-semibold text-white">Security Alerts</h3>
          {isRealTime && (
            <div className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              <span className="text-xs text-green-400">Live</span>
            </div>
          )}
        </div>
        <span className="text-sm text-slate-400">{filteredAlerts.length} alerts</span>
      </div>

      {fullView && (
        <div className="mb-6 space-y-4">
          {/* Search and Filters */}
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search alerts..."
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
        {filteredAlerts.slice(0, fullView ? 50 : 5).map((alert) => (
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
                </div>
                <h4 className="text-white font-medium">{alert.title}</h4>
                <p className="text-slate-400 text-sm mt-1">{alert.description}</p>
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
              {alert.assignee && (
                <span className="text-xs text-slate-400">Assigned to {alert.assignee}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AlertsPanel;