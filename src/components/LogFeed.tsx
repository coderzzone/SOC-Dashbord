import React, { useState, useEffect, useRef } from 'react';
import { Eye, Pause, Play, Download, Filter, Search, AlertTriangle, Info, Shield, Activity } from 'lucide-react';

interface LogEntry {
  id: string;
  timestamp: Date;
  level: 'info' | 'warning' | 'error' | 'critical';
  source: string;
  message: string;
  details?: string;
  ip?: string;
  user?: string;
}

interface LogFeedProps {
  isRealTime: boolean;
}

const LogFeed: React.FC<LogFeedProps> = ({ isRealTime }) => {
  const [logs, setLogs] = useState<LogEntry[]>([
    {
      id: '1',
      timestamp: new Date(Date.now() - 1000),
      level: 'critical',
      source: 'Firewall',
      message: 'Blocked suspicious connection attempt',
      details: 'Multiple connection attempts from blacklisted IP',
      ip: '192.168.1.100',
      user: 'anonymous'
    },
    {
      id: '2',
      timestamp: new Date(Date.now() - 2000),
      level: 'warning',
      source: 'IDS',
      message: 'Potential SQL injection detected',
      details: 'Malicious payload detected in HTTP request',
      ip: '10.0.0.45',
      user: 'web_user'
    },
    {
      id: '3',
      timestamp: new Date(Date.now() - 3000),
      level: 'info',
      source: 'Authentication',
      message: 'Successful user login',
      ip: '192.168.1.25',
      user: 'john.doe'
    }
  ]);

  const [filteredLogs, setFilteredLogs] = useState(logs);
  const [searchTerm, setSearchTerm] = useState('');
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [isPaused, setIsPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Simulate real-time log generation
  useEffect(() => {
    if (!isRealTime || isPaused) return;

    const interval = setInterval(() => {
      const newLog: LogEntry = {
        id: Date.now().toString(),
        timestamp: new Date(),
        level: getRandomLevel(),
        source: getRandomSource(),
        message: getRandomMessage(),
        details: getRandomDetails(),
        ip: getRandomIP(),
        user: getRandomUser()
      };

      setLogs(prev => [newLog, ...prev].slice(0, 1000)); // Keep only latest 1000 logs
    }, 2000);

    return () => clearInterval(interval);
  }, [isRealTime, isPaused]);

  // Filter logs
  useEffect(() => {
    let filtered = logs.filter(log => {
      const matchesSearch = log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          log.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          (log.ip && log.ip.includes(searchTerm)) ||
                          (log.user && log.user.toLowerCase().includes(searchTerm.toLowerCase()));
      const matchesLevel = levelFilter === 'all' || log.level === levelFilter;
      const matchesSource = sourceFilter === 'all' || log.source === sourceFilter;
      
      return matchesSearch && matchesLevel && matchesSource;
    });

    setFilteredLogs(filtered);
  }, [logs, searchTerm, levelFilter, sourceFilter]);

  // Auto-scroll to top when new logs arrive
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = 0;
    }
  }, [filteredLogs, autoScroll]);

  const getRandomLevel = (): LogEntry['level'] => {
    const levels: LogEntry['level'][] = ['info', 'warning', 'error', 'critical'];
    const weights = [0.6, 0.25, 0.1, 0.05]; // More info logs, fewer critical
    const random = Math.random();
    let cumulative = 0;
    
    for (let i = 0; i < levels.length; i++) {
      cumulative += weights[i];
      if (random <= cumulative) return levels[i];
    }
    return 'info';
  };

  const getRandomSource = () => {
    const sources = ['Firewall', 'IDS', 'Authentication', 'Antivirus', 'Network Monitor', 'SIEM', 'Endpoint', 'DNS'];
    return sources[Math.floor(Math.random() * sources.length)];
  };

  const getRandomMessage = () => {
    const messages = [
      'Connection established',
      'Authentication successful',
      'Blocked suspicious activity',
      'Malware signature detected',
      'Unusual network traffic pattern',
      'Failed login attempt',
      'File quarantined',
      'System health check completed',
      'Policy violation detected',
      'Backup completed successfully'
    ];
    return messages[Math.floor(Math.random() * messages.length)];
  };

  const getRandomDetails = () => {
    const details = [
      'Standard security protocol executed',
      'Automated response triggered',
      'Manual intervention required',
      'Additional monitoring activated',
      'Incident escalated to team',
      'Routine maintenance task'
    ];
    return Math.random() > 0.5 ? details[Math.floor(Math.random() * details.length)] : undefined;
  };

  const getRandomIP = () => {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  };

  const getRandomUser = () => {
    const users = ['john.doe', 'jane.smith', 'admin', 'system', 'guest', 'web_user', 'anonymous'];
    return users[Math.floor(Math.random() * users.length)];
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-400 bg-red-400/10 border-red-400/30';
      case 'error': return 'text-orange-400 bg-orange-400/10 border-orange-400/30';
      case 'warning': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30';
      case 'info': return 'text-blue-400 bg-blue-400/10 border-blue-400/30';
      default: return 'text-slate-400 bg-slate-400/10 border-slate-400/30';
    }
  };

  const getLevelIcon = (level: string) => {
    switch (level) {
      case 'critical': return AlertTriangle;
      case 'error': return AlertTriangle;
      case 'warning': return AlertTriangle;
      case 'info': return Info;
      default: return Info;
    }
  };

  const exportLogs = () => {
    const logData = filteredLogs.map(log => ({
      timestamp: log.timestamp.toISOString(),
      level: log.level,
      source: log.source,
      message: log.message,
      details: log.details || '',
      ip: log.ip || '',
      user: log.user || ''
    }));

    const blob = new Blob([JSON.stringify(logData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-logs-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const uniqueSources = [...new Set(logs.map(log => log.source))];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Eye className="w-6 h-6 text-blue-400" />
            <h2 className="text-2xl font-bold text-white">Live Security Logs</h2>
          </div>
          <div className="flex items-center space-x-2">
            {isRealTime && !isPaused && (
              <>
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-sm text-green-400">Live Feed</span>
              </>
            )}
            {(isPaused || !isRealTime) && (
              <>
                <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                <span className="text-sm text-red-400">Paused</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm transition-colors ${
              isPaused 
                ? 'bg-green-600/20 text-green-400 border border-green-600/30' 
                : 'bg-red-600/20 text-red-400 border border-red-600/30'
            }`}
          >
            {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>
          <button
            onClick={exportLogs}
            className="flex items-center space-x-2 px-3 py-2 bg-slate-600/20 text-slate-400 border border-slate-600/30 rounded-lg hover:bg-slate-600/30 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export</span>
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-4 border border-slate-700/50">
        <div className="flex flex-col lg:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
          
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Levels</option>
            <option value="critical">Critical</option>
            <option value="error">Error</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
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

          <label className="flex items-center space-x-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded bg-slate-700 border-slate-600 text-blue-500 focus:ring-blue-500"
            />
            <span>Auto-scroll</span>
          </label>
        </div>
      </div>

      {/* Log Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {['critical', 'error', 'warning', 'info'].map(level => {
          const count = filteredLogs.filter(log => log.level === level).length;
          const Icon = getLevelIcon(level);
          
          return (
            <div key={level} className={`p-4 rounded-lg border ${getLevelColor(level)}`}>
              <div className="flex items-center space-x-2">
                <Icon className="w-5 h-5" />
                <span className="font-medium">{level.toUpperCase()}</span>
              </div>
              <div className="text-2xl font-bold mt-2">{count}</div>
            </div>
          );
        })}
      </div>

      {/* Log Entries */}
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl border border-slate-700/50">
        <div className="p-4 border-b border-slate-700/50">
          <div className="flex items-center justify-between">
            <span className="text-white font-medium">Log Entries</span>
            <span className="text-sm text-slate-400">{filteredLogs.length} entries</span>
          </div>
        </div>
        
        <div 
          ref={logContainerRef}
          className="max-h-96 overflow-y-auto p-4 space-y-2"
        >
          {filteredLogs.map((log) => {
            const Icon = getLevelIcon(log.level);
            
            return (
              <div 
                key={log.id} 
                className="flex items-start space-x-4 p-3 bg-slate-700/30 rounded-lg border border-slate-600/30 hover:bg-slate-700/50 transition-colors"
              >
                <div className={`flex-shrink-0 w-8 h-8 rounded-full border flex items-center justify-center ${getLevelColor(log.level)}`}>
                  <Icon className="w-4 h-4" />
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-4 mb-1">
                    <span className="text-slate-400 text-sm font-mono">
                      {log.timestamp.toLocaleTimeString()}.{log.timestamp.getMilliseconds().toString().padStart(3, '0')}
                    </span>
                    <span className={`px-2 py-1 rounded-md text-xs font-medium ${getLevelColor(log.level)}`}>
                      {log.level.toUpperCase()}
                    </span>
                    <span className="text-slate-300 text-sm">{log.source}</span>
                  </div>
                  
                  <p className="text-white font-medium">{log.message}</p>
                  
                  {log.details && (
                    <p className="text-slate-400 text-sm mt-1">{log.details}</p>
                  )}
                  
                  <div className="flex items-center space-x-4 mt-2 text-xs text-slate-500">
                    {log.ip && <span>IP: {log.ip}</span>}
                    {log.user && <span>User: {log.user}</span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default LogFeed;