import React, { useState, useEffect } from 'react';
import { TrendingUp, TrendingDown, Clock, Shield, AlertTriangle, CheckCircle, Activity, Target } from 'lucide-react';

interface MetricData {
  label: string;
  value: number;
  change: number;
  unit: string;
  trend: 'up' | 'down' | 'stable';
  good: boolean; // whether the trend direction is good or bad
}

const KPIMetrics: React.FC = () => {
  const [metrics, setMetrics] = useState<MetricData[]>([
    {
      label: 'Mean Time to Resolution',
      value: 45,
      change: -12,
      unit: 'minutes',
      trend: 'down',
      good: true
    },
    {
      label: 'Mean Time to Detection',
      value: 8,
      change: -5,
      unit: 'minutes',
      trend: 'down',
      good: true
    },
    {
      label: 'Alert Volume',
      value: 1247,
      change: 15,
      unit: 'alerts/day',
      trend: 'up',
      good: false
    },
    {
      label: 'False Positive Rate',
      value: 12,
      change: -3,
      unit: '%',
      trend: 'down',
      good: true
    },
    {
      label: 'Incident Response Time',
      value: 15,
      change: -8,
      unit: 'seconds',
      trend: 'down',
      good: true
    },
    {
      label: 'System Uptime',
      value: 99.8,
      change: 0.2,
      unit: '%',
      trend: 'up',
      good: true
    }
  ]);

  const [severityDistribution, setSeverityDistribution] = useState({
    critical: 8,
    high: 23,
    medium: 45,
    low: 67,
    info: 124
  });

  // Simulate real-time metric updates
  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics(prev => prev.map(metric => ({
        ...metric,
        value: Math.max(0, metric.value + (Math.random() - 0.5) * 2),
        change: (Math.random() - 0.5) * 10
      })));

      setSeverityDistribution(prev => ({
        critical: Math.max(0, prev.critical + Math.floor((Math.random() - 0.5) * 3)),
        high: Math.max(0, prev.high + Math.floor((Math.random() - 0.5) * 5)),
        medium: Math.max(0, prev.medium + Math.floor((Math.random() - 0.5) * 8)),
        low: Math.max(0, prev.low + Math.floor((Math.random() - 0.5) * 10)),
        info: Math.max(0, prev.info + Math.floor((Math.random() - 0.5) * 15))
      }));
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  const getMetricIcon = (label: string) => {
    if (label.includes('Time')) return Clock;
    if (label.includes('Alert')) return AlertTriangle;
    if (label.includes('Uptime')) return CheckCircle;
    if (label.includes('Response')) return Activity;
    return Target;
  };

  const getTrendColor = (trend: string, good: boolean) => {
    if (trend === 'stable') return 'text-slate-400';
    
    const isPositiveTrend = trend === 'up';
    const shouldBeGreen = (isPositiveTrend && good) || (!isPositiveTrend && !good);
    
    return shouldBeGreen ? 'text-green-400' : 'text-red-400';
  };

  const total = Object.values(severityDistribution).reduce((sum, value) => sum + value, 0);

  return (
    <div className="space-y-6">
      {/* Main KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {metrics.map((metric, index) => {
          const Icon = getMetricIcon(metric.label);
          const TrendIcon = metric.trend === 'up' ? TrendingUp : 
                          metric.trend === 'down' ? TrendingDown : Activity;
          
          return (
            <div key={index} className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700/50">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-2">
                  <Icon className="w-5 h-5 text-blue-400" />
                  <h3 className="text-sm font-medium text-slate-300">{metric.label}</h3>
                </div>
                <div className={`flex items-center space-x-1 ${getTrendColor(metric.trend, metric.good)}`}>
                  <TrendIcon className="w-4 h-4" />
                  <span className="text-sm font-medium">
                    {metric.change > 0 ? '+' : ''}{metric.change.toFixed(1)}%
                  </span>
                </div>
              </div>
              
              <div className="flex items-baseline space-x-2">
                <span className="text-2xl font-bold text-white">
                  {metric.value.toFixed(metric.unit === '%' ? 1 : 0)}
                </span>
                <span className="text-sm text-slate-400">{metric.unit}</span>
              </div>
              
              <div className="mt-4 h-2 bg-slate-700/50 rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-1000 ${
                    metric.good ? 'bg-green-400' : 'bg-blue-400'
                  }`}
                  style={{ 
                    width: `${Math.min(100, Math.max(10, (metric.value / (metric.label.includes('%') ? 100 : 60)) * 100))}%` 
                  }}
                ></div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700/50">
          <div className="flex items-center space-x-2 mb-6">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            <h3 className="text-lg font-semibold text-white">Alert Severity Distribution</h3>
          </div>
          
          <div className="space-y-4">
            {Object.entries(severityDistribution).map(([severity, count]) => {
              const percentage = (count / total) * 100;
              const colors = {
                critical: 'bg-red-400',
                high: 'bg-orange-400',
                medium: 'bg-yellow-400',
                low: 'bg-blue-400',
                info: 'bg-green-400'
              };
              
              return (
                <div key={severity} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-slate-300 capitalize">{severity}</span>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm text-slate-400">{count}</span>
                      <span className="text-xs text-slate-500">({percentage.toFixed(1)}%)</span>
                    </div>
                  </div>
                  <div className="h-2 bg-slate-700/50 rounded-full overflow-hidden">
                    <div 
                      className={`h-full transition-all duration-1000 ${colors[severity as keyof typeof colors]}`}
                      style={{ width: `${percentage}%` }}
                    ></div>
                  </div>
                </div>
              );
            })}
          </div>
          
          <div className="mt-6 pt-4 border-t border-slate-700/50">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Total Alerts</span>
              <span className="text-white font-medium">{total}</span>
            </div>
          </div>
        </div>

        {/* Performance Trends */}
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700/50">
          <div className="flex items-center space-x-2 mb-6">
            <Activity className="w-5 h-5 text-green-400" />
            <h3 className="text-lg font-semibold text-white">Performance Trends</h3>
          </div>
          
          <div className="space-y-6">
            {/* Response Time Trend */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-300">Average Response Time</span>
                <span className="text-sm text-green-400">↓ 15% this week</span>
              </div>
              <div className="h-12 bg-slate-700/30 rounded-lg relative overflow-hidden">
                <div className="absolute inset-0 flex items-end space-x-1 px-2 py-1">
                  {[65, 58, 52, 48, 45, 42, 40].map((value, index) => (
                    <div 
                      key={index}
                      className="flex-1 bg-green-400/30 rounded-sm border-t-2 border-green-400"
                      style={{ height: `${(value / 70) * 100}%` }}
                    ></div>
                  ))}
                </div>
              </div>
              <div className="flex justify-between text-xs text-slate-500 mt-1">
                <span>7 days ago</span>
                <span>Today</span>
              </div>
            </div>

            {/* Alert Volume Trend */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-300">Daily Alert Volume</span>
                <span className="text-sm text-red-400">↑ 8% this week</span>
              </div>
              <div className="h-12 bg-slate-700/30 rounded-lg relative overflow-hidden">
                <div className="absolute inset-0 flex items-end space-x-1 px-2 py-1">
                  {[1100, 1150, 1200, 1180, 1220, 1260, 1247].map((value, index) => (
                    <div 
                      key={index}
                      className="flex-1 bg-orange-400/30 rounded-sm border-t-2 border-orange-400"
                      style={{ height: `${((value - 1000) / 300) * 100}%` }}
                    ></div>
                  ))}
                </div>
              </div>
              <div className="flex justify-between text-xs text-slate-500 mt-1">
                <span>7 days ago</span>
                <span>Today</span>
              </div>
            </div>

            {/* Detection Accuracy */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-300">Detection Accuracy</span>
                <span className="text-sm text-green-400">↑ 3% this week</span>
              </div>
              <div className="flex items-center space-x-4">
                <div className="flex-1 h-3 bg-slate-700/50 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-400 rounded-full transition-all duration-1000" style={{ width: '92%' }}></div>
                </div>
                <span className="text-sm font-medium text-white">92%</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default KPIMetrics;