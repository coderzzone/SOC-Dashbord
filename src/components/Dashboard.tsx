import React, { useState, useEffect } from 'react';
import { AlertTriangle, Shield, Clock, Users, TrendingUp, Activity, Search, Filter, Tag, Play, Pause, Settings, Bell, Eye, EyeOff } from 'lucide-react';
import AlertsPanel from './AlertsPanel';
import IncidentTimeline from './IncidentTimeline';
import CaseManagement from './CaseManagement';
import LogFeed from './LogFeed';
import KPIMetrics from './KPIMetrics';
import UserRoles from './UserRoles';

interface DashboardProps {
  currentUser: {
    id: string;
    name: string;
    email: string;
    role: 'soc_analyst' | 'incident_manager' | 'admin';
  };
  onLogout: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ currentUser, onLogout }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [isRealTimeEnabled, setIsRealTimeEnabled] = useState(true);
  const [alertCount, setAlertCount] = useState(24);
  const [criticalIncidents, setCriticalIncidents] = useState(3);

  // Simulate real-time updates
  useEffect(() => {
    if (!isRealTimeEnabled) return;
    
    const interval = setInterval(() => {
      if (Math.random() > 0.7) {
        setAlertCount(prev => prev + 1);
      }
      if (Math.random() > 0.9) {
        setCriticalIncidents(prev => Math.max(0, prev + (Math.random() > 0.5 ? 1 : -1)));
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [isRealTimeEnabled]);

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
    { id: 'incidents', label: 'Incidents', icon: Shield },
    { id: 'cases', label: 'Cases', icon: Clock },
    { id: 'logs', label: 'Live Logs', icon: Eye },
    { id: 'users', label: 'Users', icon: Users, adminOnly: true },
  ];

  const filteredTabs = tabs.filter(tab => 
    !tab.adminOnly || currentUser.role === 'admin'
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="bg-slate-800/50 backdrop-blur-md border-b border-slate-700/50 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <Shield className="w-8 h-8 text-blue-400" />
              <h1 className="text-xl font-bold text-white">SecOps Dashboard</h1>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Bell className="w-5 h-5 text-slate-400" />
                <span className="text-sm text-slate-300">{alertCount} Active Alerts</span>
              </div>
              
              <button
                onClick={() => setIsRealTimeEnabled(!isRealTimeEnabled)}
                className={`flex items-center space-x-2 px-3 py-1 rounded-md text-sm ${
                  isRealTimeEnabled 
                    ? 'bg-green-600/20 text-green-400 border border-green-600/30' 
                    : 'bg-slate-600/20 text-slate-400 border border-slate-600/30'
                }`}
              >
                {isRealTimeEnabled ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                <span>{isRealTimeEnabled ? 'Live' : 'Paused'}</span>
              </button>
              
              <div className="flex items-center space-x-2 text-slate-300">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-sm">{currentUser.name}</span>
                <span className="text-xs bg-slate-700 px-2 py-1 rounded-full">
                  {currentUser.role.replace('_', ' ').toUpperCase()}
                </span>
                <button
                  onClick={onLogout}
                  className="ml-2 px-3 py-1 text-xs bg-red-600/20 text-red-400 border border-red-600/30 rounded-full hover:bg-red-600/30 transition-colors"
                >
                  Logout
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-slate-800/30 backdrop-blur-sm border-b border-slate-700/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8 overflow-x-auto">
            {filteredTabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap transition-colors ${
                    activeTab === tab.id
                      ? 'border-blue-400 text-blue-400'
                      : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-300'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Quick Stats */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700/50">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Active Alerts</p>
                    <p className="text-3xl font-bold text-white">{alertCount}</p>
                  </div>
                  <AlertTriangle className="w-8 h-8 text-orange-400" />
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <TrendingUp className="w-4 h-4 text-green-400 mr-2" />
                  <span className="text-green-400">12% increase</span>
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700/50">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Critical Incidents</p>
                    <p className="text-3xl font-bold text-white">{criticalIncidents}</p>
                  </div>
                  <Shield className="w-8 h-8 text-red-400" />
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">Avg MTTR: 45m</span>
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700/50">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Open Cases</p>
                    <p className="text-3xl font-bold text-white">18</p>
                  </div>
                  <Clock className="w-8 h-8 text-blue-400" />
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <span className="text-slate-400">5 assigned to you</span>
                </div>
              </div>

              <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700/50">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-slate-400 text-sm">Team Members</p>
                    <p className="text-3xl font-bold text-white">12</p>
                  </div>
                  <Users className="w-8 h-8 text-green-400" />
                </div>
                <div className="mt-4 flex items-center text-sm">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                  <span className="text-green-400">8 online</span>
                </div>
              </div>
            </div>

            {/* KPI Metrics */}
            <KPIMetrics />
            
            {/* Recent Activity Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <AlertsPanel isRealTime={isRealTimeEnabled} />
              <IncidentTimeline />
            </div>
          </div>
        )}

        {activeTab === 'alerts' && <AlertsPanel isRealTime={isRealTimeEnabled} fullView />}
        {activeTab === 'incidents' && <IncidentTimeline fullView />}
        {activeTab === 'cases' && <CaseManagement />}
        {activeTab === 'logs' && <LogFeed isRealTime={isRealTimeEnabled} />}
        {activeTab === 'users' && currentUser.role === 'admin' && <UserRoles />}
      </main>
    </div>
  );
};

export default Dashboard;