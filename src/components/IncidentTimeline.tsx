import React, { useState, useEffect } from 'react';
import { Shield, Clock, User, Activity, ChevronDown, ChevronUp, Filter } from 'lucide-react';

interface TimelineEvent {
  id: string;
  timestamp: Date;
  type: 'incident_created' | 'status_changed' | 'assignment' | 'escalation' | 'resolution';
  title: string;
  description: string;
  user: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  relatedIncident: string;
}

interface IncidentTimelineProps {
  fullView?: boolean;
}

const IncidentTimeline: React.FC<IncidentTimelineProps> = ({ fullView = false }) => {
  const [events, setEvents] = useState<TimelineEvent[]>([
    {
      id: '1',
      timestamp: new Date(Date.now() - 300000),
      type: 'incident_created',
      title: 'Critical Security Incident Created',
      description: 'Advanced persistent threat detected in network segment 192.168.10.0/24',
      user: 'System',
      severity: 'critical',
      relatedIncident: 'INC-2024-001'
    },
    {
      id: '2',
      timestamp: new Date(Date.now() - 600000),
      type: 'assignment',
      title: 'Incident Assigned',
      description: 'Incident INC-2024-002 assigned to Senior Security Analyst',
      user: 'Jane Smith',
      relatedIncident: 'INC-2024-002'
    },
    {
      id: '3',
      timestamp: new Date(Date.now() - 900000),
      type: 'escalation',
      title: 'Incident Escalated',
      description: 'Escalated to Incident Response Team due to potential data breach',
      user: 'John Doe',
      severity: 'high',
      relatedIncident: 'INC-2024-003'
    },
    {
      id: '4',
      timestamp: new Date(Date.now() - 1200000),
      type: 'status_changed',
      title: 'Status Updated',
      description: 'Incident status changed from "Investigating" to "Containment"',
      user: 'Mike Johnson',
      relatedIncident: 'INC-2024-001'
    },
    {
      id: '5',
      timestamp: new Date(Date.now() - 1800000),
      type: 'resolution',
      title: 'Incident Resolved',
      description: 'Security incident successfully contained and resolved',
      user: 'Sarah Wilson',
      relatedIncident: 'INC-2024-004'
    }
  ]);

  const [filteredEvents, setFilteredEvents] = useState(events);
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(new Set());
  const [typeFilter, setTypeFilter] = useState<string>('all');

  useEffect(() => {
    let filtered = events;
    if (typeFilter !== 'all') {
      filtered = events.filter(event => event.type === typeFilter);
    }
    setFilteredEvents(filtered);
  }, [events, typeFilter]);

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'incident_created': return Shield;
      case 'assignment': return User;
      case 'escalation': return Activity;
      case 'status_changed': return Clock;
      case 'resolution': return Shield;
      default: return Activity;
    }
  };

  const getEventColor = (type: string, severity?: string) => {
    if (severity) {
      switch (severity) {
        case 'critical': return 'text-red-400 bg-red-400/10 border-red-400/30';
        case 'high': return 'text-orange-400 bg-orange-400/10 border-orange-400/30';
        case 'medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30';
        case 'low': return 'text-blue-400 bg-blue-400/10 border-blue-400/30';
      }
    }
    
    switch (type) {
      case 'incident_created': return 'text-red-400 bg-red-400/10 border-red-400/30';
      case 'assignment': return 'text-blue-400 bg-blue-400/10 border-blue-400/30';
      case 'escalation': return 'text-orange-400 bg-orange-400/10 border-orange-400/30';
      case 'status_changed': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30';
      case 'resolution': return 'text-green-400 bg-green-400/10 border-green-400/30';
      default: return 'text-slate-400 bg-slate-400/10 border-slate-400/30';
    }
  };

  const toggleExpanded = (eventId: string) => {
    const newExpanded = new Set(expandedEvents);
    if (newExpanded.has(eventId)) {
      newExpanded.delete(eventId);
    } else {
      newExpanded.add(eventId);
    }
    setExpandedEvents(newExpanded);
  };

  return (
    <div className={`bg-slate-800/50 backdrop-blur-sm rounded-xl border border-slate-700/50 ${fullView ? 'p-6' : 'p-4'}`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <Activity className="w-5 h-5 text-blue-400" />
          <h3 className="text-lg font-semibold text-white">Incident Timeline</h3>
        </div>
        <span className="text-sm text-slate-400">{filteredEvents.length} events</span>
      </div>

      {fullView && (
        <div className="mb-6">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Events</option>
            <option value="incident_created">Incidents Created</option>
            <option value="assignment">Assignments</option>
            <option value="escalation">Escalations</option>
            <option value="status_changed">Status Changes</option>
            <option value="resolution">Resolutions</option>
          </select>
        </div>
      )}

      <div className="space-y-4 max-h-96 overflow-y-auto">
        {filteredEvents.slice(0, fullView ? 20 : 5).map((event, index) => {
          const Icon = getEventIcon(event.type);
          const isExpanded = expandedEvents.has(event.id);
          
          return (
            <div key={event.id} className="relative">
              {/* Timeline line */}
              {index < filteredEvents.length - 1 && (
                <div className="absolute left-6 top-12 w-0.5 h-8 bg-slate-600/50"></div>
              )}
              
              <div className="flex items-start space-x-4">
                <div className={`flex-shrink-0 w-12 h-12 rounded-full border-2 flex items-center justify-center ${getEventColor(event.type, event.severity)}`}>
                  <Icon className="w-5 h-5" />
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="bg-slate-700/30 rounded-lg p-4 border border-slate-600/30">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <h4 className="text-white font-medium">{event.title}</h4>
                        <div className="flex items-center space-x-2 mt-1">
                          <span className="text-xs text-slate-400">{event.relatedIncident}</span>
                          {event.severity && (
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getEventColor(event.type, event.severity)}`}>
                              {event.severity.toUpperCase()}
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-slate-400">
                          {event.timestamp.toLocaleTimeString()}
                        </span>
                        {fullView && (
                          <button
                            onClick={() => toggleExpanded(event.id)}
                            className="text-slate-400 hover:text-white transition-colors"
                          >
                            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                          </button>
                        )}
                      </div>
                    </div>
                    
                    <p className="text-slate-300 text-sm">{event.description}</p>
                    
                    {fullView && isExpanded && (
                      <div className="mt-3 pt-3 border-t border-slate-600/30">
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-slate-400">User:</span>
                            <span className="text-white ml-2">{event.user}</span>
                          </div>
                          <div>
                            <span className="text-slate-400">Event Type:</span>
                            <span className="text-white ml-2">{event.type.replace('_', ' ')}</span>
                          </div>
                          <div>
                            <span className="text-slate-400">Timestamp:</span>
                            <span className="text-white ml-2">{event.timestamp.toLocaleString()}</span>
                          </div>
                          <div>
                            <span className="text-slate-400">Related:</span>
                            <span className="text-white ml-2">{event.relatedIncident}</span>
                          </div>
                        </div>
                      </div>
                    )}
                    
                    <div className="flex items-center justify-between mt-3">
                      <span className="text-xs text-slate-400">by {event.user}</span>
                      <span className="text-xs text-slate-500">
                        {Math.floor((Date.now() - event.timestamp.getTime()) / 60000)}m ago
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default IncidentTimeline;