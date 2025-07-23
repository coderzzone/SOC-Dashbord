import React, { useState } from 'react';
import { Clock, User, Tag, Search, Filter, Plus, Edit, Trash2, CheckCircle, Circle, AlertCircle } from 'lucide-react';

interface Case {
  id: string;
  title: string;
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'in_progress' | 'under_review' | 'closed';
  assignee: string;
  reporter: string;
  createdAt: Date;
  updatedAt: Date;
  dueDate?: Date;
  tags: string[];
  relatedIncidents: string[];
}

const CaseManagement: React.FC = () => {
  const [cases, setCases] = useState<Case[]>([
    {
      id: 'CASE-001',
      title: 'Investigation: Suspicious Data Exfiltration',
      description: 'Investigate potential data exfiltration detected in network logs from server DB-PROD-01',
      priority: 'critical',
      status: 'in_progress',
      assignee: 'John Doe',
      reporter: 'Security System',
      createdAt: new Date(Date.now() - 86400000),
      updatedAt: new Date(Date.now() - 3600000),
      dueDate: new Date(Date.now() + 172800000),
      tags: ['data-breach', 'investigation', 'database'],
      relatedIncidents: ['INC-2024-001', 'INC-2024-003']
    },
    {
      id: 'CASE-002',
      title: 'Malware Analysis: Trojan.Generic',
      description: 'Analyze and contain malware sample detected on endpoint WS-045',
      priority: 'high',
      status: 'under_review',
      assignee: 'Jane Smith',
      reporter: 'Mike Johnson',
      createdAt: new Date(Date.now() - 172800000),
      updatedAt: new Date(Date.now() - 7200000),
      tags: ['malware', 'endpoint', 'analysis'],
      relatedIncidents: ['INC-2024-005']
    },
    {
      id: 'CASE-003',
      title: 'Phishing Campaign Assessment',
      description: 'Assess and mitigate recent phishing campaign targeting finance department',
      priority: 'medium',
      status: 'open',
      assignee: 'Sarah Wilson',
      reporter: 'Finance Team',
      createdAt: new Date(Date.now() - 259200000),
      updatedAt: new Date(Date.now() - 86400000),
      dueDate: new Date(Date.now() + 86400000),
      tags: ['phishing', 'email', 'social-engineering'],
      relatedIncidents: ['INC-2024-007']
    }
  ]);

  const [filteredCases, setFilteredCases] = useState(cases);
  const [searchTerm, setSearchTerm] = useState('');
  const [priorityFilter, setPriorityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);

  React.useEffect(() => {
    let filtered = cases.filter(caseItem => {
      const matchesSearch = caseItem.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          caseItem.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          caseItem.assignee.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesPriority = priorityFilter === 'all' || caseItem.priority === priorityFilter;
      const matchesStatus = statusFilter === 'all' || caseItem.status === statusFilter;
      
      return matchesSearch && matchesPriority && matchesStatus;
    });

    setFilteredCases(filtered);
  }, [cases, searchTerm, priorityFilter, statusFilter]);

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'text-red-400 bg-red-400/10 border-red-400/20';
      case 'high': return 'text-orange-400 bg-orange-400/10 border-orange-400/20';
      case 'medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
      case 'low': return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
      default: return 'text-slate-400 bg-slate-400/10 border-slate-400/20';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'text-red-400 bg-red-400/10';
      case 'in_progress': return 'text-blue-400 bg-blue-400/10';
      case 'under_review': return 'text-yellow-400 bg-yellow-400/10';
      case 'closed': return 'text-green-400 bg-green-400/10';
      default: return 'text-slate-400 bg-slate-400/10';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open': return Circle;
      case 'in_progress': return AlertCircle;
      case 'under_review': return Clock;
      case 'closed': return CheckCircle;
      default: return Circle;
    }
  };

  const updateCaseStatus = (caseId: string, newStatus: Case['status']) => {
    setCases(prev => prev.map(caseItem => 
      caseItem.id === caseId 
        ? { ...caseItem, status: newStatus, updatedAt: new Date() }
        : caseItem
    ));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Case Management</h2>
          <p className="text-slate-400 mt-1">Track and manage security investigation cases</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          <span>New Case</span>
        </button>
      </div>

      {/* Filters */}
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-4 border border-slate-700/50">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search cases..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
          
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Priorities</option>
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
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="under_review">Under Review</option>
            <option value="closed">Closed</option>
          </select>
        </div>
      </div>

      {/* Cases Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {filteredCases.map((caseItem) => {
          const StatusIcon = getStatusIcon(caseItem.status);
          
          return (
            <div
              key={caseItem.id}
              className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700/50 hover:bg-slate-700/50 transition-colors cursor-pointer"
              onClick={() => setSelectedCase(caseItem)}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getPriorityColor(caseItem.priority)}`}>
                    {caseItem.priority.toUpperCase()}
                  </span>
                  <span className="text-slate-400 text-sm">{caseItem.id}</span>
                </div>
                <div className="flex items-center space-x-1">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      // Handle edit
                    }}
                    className="p-1 text-slate-400 hover:text-white transition-colors"
                  >
                    <Edit className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <h3 className="text-white font-semibold mb-2">{caseItem.title}</h3>
              <p className="text-slate-400 text-sm mb-4 line-clamp-2">{caseItem.description}</p>

              <div className={`flex items-center space-x-2 mb-4 px-2 py-1 rounded-md ${getStatusColor(caseItem.status)}`}>
                <StatusIcon className="w-4 h-4" />
                <span className="text-sm font-medium">{caseItem.status.replace('_', ' ').toUpperCase()}</span>
              </div>

              <div className="space-y-2 mb-4">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Assignee:</span>
                  <span className="text-white">{caseItem.assignee}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Created:</span>
                  <span className="text-white">{caseItem.createdAt.toLocaleDateString()}</span>
                </div>
                {caseItem.dueDate && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-400">Due:</span>
                    <span className={`${caseItem.dueDate < new Date() ? 'text-red-400' : 'text-white'}`}>
                      {caseItem.dueDate.toLocaleDateString()}
                    </span>
                  </div>
                )}
              </div>

              <div className="flex flex-wrap gap-1 mb-4">
                {caseItem.tags.map((tag) => (
                  <span key={tag} className="px-2 py-1 bg-slate-600/50 text-slate-300 text-xs rounded-md flex items-center">
                    <Tag className="w-3 h-3 mr-1" />
                    {tag}
                  </span>
                ))}
              </div>

              {caseItem.relatedIncidents.length > 0 && (
                <div className="text-sm">
                  <span className="text-slate-400">Related: </span>
                  <span className="text-blue-400">{caseItem.relatedIncidents.join(', ')}</span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Case Detail Modal */}
      {selectedCase && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-800 rounded-xl border border-slate-700 max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">{selectedCase.title}</h2>
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getPriorityColor(selectedCase.priority)}`}>
                      {selectedCase.priority.toUpperCase()}
                    </span>
                    <span className="text-slate-400">{selectedCase.id}</span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedCase(null)}
                  className="text-slate-400 hover:text-white"
                >
                  ×
                </button>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-white font-medium mb-2">Description</h3>
                  <p className="text-slate-300">{selectedCase.description}</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-white font-medium mb-2">Status</h4>
                    <select
                      value={selectedCase.status}
                      onChange={(e) => updateCaseStatus(selectedCase.id, e.target.value as Case['status'])}
                      className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="open">Open</option>
                      <option value="in_progress">In Progress</option>
                      <option value="under_review">Under Review</option>
                      <option value="closed">Closed</option>
                    </select>
                  </div>
                  <div>
                    <h4 className="text-white font-medium mb-2">Assignee</h4>
                    <p className="text-slate-300">{selectedCase.assignee}</p>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-white font-medium mb-2">Reporter</h4>
                    <p className="text-slate-300">{selectedCase.reporter}</p>
                  </div>
                  <div>
                    <h4 className="text-white font-medium mb-2">Created</h4>
                    <p className="text-slate-300">{selectedCase.createdAt.toLocaleString()}</p>
                  </div>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-2">Tags</h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedCase.tags.map((tag) => (
                      <span key={tag} className="px-2 py-1 bg-slate-600/50 text-slate-300 text-sm rounded-md flex items-center">
                        <Tag className="w-3 h-3 mr-1" />
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-2">Related Incidents</h4>
                  <div className="space-y-2">
                    {selectedCase.relatedIncidents.map((incident) => (
                      <div key={incident} className="px-3 py-2 bg-slate-700/50 rounded-lg">
                        <span className="text-blue-400">{incident}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CaseManagement;