import React, { useState } from 'react';
import { Users, Shield, Eye, Edit, Plus, Search, Filter, UserCheck, UserX, Crown, Settings } from 'lucide-react';

interface User {
  id: string;
  name: string;
  email: string;
  role: 'soc_analyst' | 'incident_manager' | 'admin';
  status: 'active' | 'inactive';
  lastLogin: Date;
  permissions: string[];
  department: string;
}

const UserRoles: React.FC = () => {
  const [users, setUsers] = useState<User[]>([
    {
      id: '1',
      name: 'John Doe',
      email: 'john.doe@company.com',
      role: 'soc_analyst',
      status: 'active',
      lastLogin: new Date(Date.now() - 3600000),
      permissions: ['view_alerts', 'acknowledge_alerts', 'create_cases'],
      department: 'Security Operations'
    },
    {
      id: '2',
      name: 'Jane Smith',
      email: 'jane.smith@company.com',
      role: 'incident_manager',
      status: 'active',
      lastLogin: new Date(Date.now() - 1800000),
      permissions: ['view_alerts', 'acknowledge_alerts', 'create_cases', 'assign_cases', 'escalate_incidents'],
      department: 'Security Operations'
    },
    {
      id: '3',
      name: 'Mike Johnson',
      email: 'mike.johnson@company.com',
      role: 'admin',
      status: 'active',
      lastLogin: new Date(Date.now() - 900000),
      permissions: ['full_access'],
      department: 'IT Administration'
    },
    {
      id: '4',
      name: 'Sarah Wilson',
      email: 'sarah.wilson@company.com',
      role: 'soc_analyst',
      status: 'inactive',
      lastLogin: new Date(Date.now() - 86400000),
      permissions: ['view_alerts', 'acknowledge_alerts'],
      department: 'Security Operations'
    }
  ]);

  const [filteredUsers, setFilteredUsers] = useState(users);
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);

  React.useEffect(() => {
    let filtered = users.filter(user => {
      const matchesSearch = user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          user.department.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesRole = roleFilter === 'all' || user.role === roleFilter;
      const matchesStatus = statusFilter === 'all' || user.status === statusFilter;
      
      return matchesSearch && matchesRole && matchesStatus;
    });

    setFilteredUsers(filtered);
  }, [users, searchTerm, roleFilter, statusFilter]);

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin': return 'text-red-400 bg-red-400/10 border-red-400/20';
      case 'incident_manager': return 'text-orange-400 bg-orange-400/10 border-orange-400/20';
      case 'soc_analyst': return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
      default: return 'text-slate-400 bg-slate-400/10 border-slate-400/20';
    }
  };

  const getRoleIcon = (role: string) => {
    switch (role) {
      case 'admin': return Crown;
      case 'incident_manager': return Shield;
      case 'soc_analyst': return Eye;
      default: return Users;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-400 bg-green-400/10';
      case 'inactive': return 'text-red-400 bg-red-400/10';
      default: return 'text-slate-400 bg-slate-400/10';
    }
  };

  const toggleUserStatus = (userId: string) => {
    setUsers(prev => prev.map(user => 
      user.id === userId 
        ? { ...user, status: user.status === 'active' ? 'inactive' : 'active' }
        : user
    ));
  };

  const rolePermissions = {
    soc_analyst: [
      'view_alerts',
      'acknowledge_alerts', 
      'create_cases',
      'view_logs',
      'export_reports'
    ],
    incident_manager: [
      'view_alerts',
      'acknowledge_alerts',
      'create_cases',
      'assign_cases',
      'escalate_incidents',
      'view_logs',
      'export_reports',
      'manage_team'
    ],
    admin: [
      'full_access'
    ]
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">User Management</h2>
          <p className="text-slate-400 mt-1">Manage user accounts and role-based permissions</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          <span>Add User</span>
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
                placeholder="Search users..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
          
          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Roles</option>
            <option value="admin">Admin</option>
            <option value="incident_manager">Incident Manager</option>
            <option value="soc_analyst">SOC Analyst</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
        </div>
      </div>

      {/* User Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-4 border border-slate-700/50">
          <div className="flex items-center space-x-2">
            <Users className="w-5 h-5 text-blue-400" />
            <span className="text-slate-300">Total Users</span>
          </div>
          <div className="text-2xl font-bold text-white mt-2">{users.length}</div>
        </div>
        
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-4 border border-slate-700/50">
          <div className="flex items-center space-x-2">
            <UserCheck className="w-5 h-5 text-green-400" />
            <span className="text-slate-300">Active</span>
          </div>
          <div className="text-2xl font-bold text-white mt-2">
            {users.filter(u => u.status === 'active').length}
          </div>
        </div>
        
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-4 border border-slate-700/50">
          <div className="flex items-center space-x-2">
            <Crown className="w-5 h-5 text-red-400" />
            <span className="text-slate-300">Admins</span>
          </div>
          <div className="text-2xl font-bold text-white mt-2">
            {users.filter(u => u.role === 'admin').length}
          </div>
        </div>
        
        <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-4 border border-slate-700/50">
          <div className="flex items-center space-x-2">
            <Shield className="w-5 h-5 text-orange-400" />
            <span className="text-slate-300">Managers</span>
          </div>
          <div className="text-2xl font-bold text-white mt-2">
            {users.filter(u => u.role === 'incident_manager').length}
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl border border-slate-700/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-700/50 border-b border-slate-600/50">
              <tr>
                <th className="text-left py-3 px-4 text-slate-300 font-medium">User</th>
                <th className="text-left py-3 px-4 text-slate-300 font-medium">Role</th>
                <th className="text-left py-3 px-4 text-slate-300 font-medium">Department</th>
                <th className="text-left py-3 px-4 text-slate-300 font-medium">Status</th>
                <th className="text-left py-3 px-4 text-slate-300 font-medium">Last Login</th>
                <th className="text-left py-3 px-4 text-slate-300 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((user) => {
                const RoleIcon = getRoleIcon(user.role);
                
                return (
                  <tr key={user.id} className="border-b border-slate-700/30 hover:bg-slate-700/20 transition-colors">
                    <td className="py-3 px-4">
                      <div>
                        <div className="text-white font-medium">{user.name}</div>
                        <div className="text-slate-400 text-sm">{user.email}</div>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className={`flex items-center space-x-2 px-2 py-1 rounded-full text-xs font-medium border w-fit ${getRoleColor(user.role)}`}>
                        <RoleIcon className="w-3 h-3" />
                        <span>{user.role.replace('_', ' ').toUpperCase()}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{user.department}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(user.status)}`}>
                        {user.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300 text-sm">
                      {user.lastLogin.toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setSelectedUser(user)}
                          className="p-1 text-slate-400 hover:text-blue-400 transition-colors"
                          title="View Details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => toggleUserStatus(user.id)}
                          className={`p-1 transition-colors ${
                            user.status === 'active' 
                              ? 'text-slate-400 hover:text-red-400' 
                              : 'text-slate-400 hover:text-green-400'
                          }`}
                          title={user.status === 'active' ? 'Deactivate' : 'Activate'}
                        >
                          {user.status === 'active' ? <UserX className="w-4 h-4" /> : <UserCheck className="w-4 h-4" />}
                        </button>
                        <button
                          className="p-1 text-slate-400 hover:text-white transition-colors"
                          title="Edit User"
                        >
                          <Settings className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* User Detail Modal */}
      {selectedUser && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-800 rounded-xl border border-slate-700 max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h2 className="text-xl font-bold text-white mb-2">{selectedUser.name}</h2>
                  <p className="text-slate-400">{selectedUser.email}</p>
                </div>
                <button
                  onClick={() => setSelectedUser(null)}
                  className="text-slate-400 hover:text-white"
                >
                  ×
                </button>
              </div>

              <div className="space-y-6">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-white font-medium mb-2">Role</h4>
                    <div className={`flex items-center space-x-2 px-3 py-2 rounded-lg border ${getRoleColor(selectedUser.role)}`}>
                      {React.createElement(getRoleIcon(selectedUser.role), { className: "w-4 h-4" })}
                      <span>{selectedUser.role.replace('_', ' ').toUpperCase()}</span>
                    </div>
                  </div>
                  <div>
                    <h4 className="text-white font-medium mb-2">Status</h4>
                    <span className={`px-3 py-2 rounded-lg ${getStatusColor(selectedUser.status)}`}>
                      {selectedUser.status.toUpperCase()}
                    </span>
                  </div>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-2">Department</h4>
                  <p className="text-slate-300">{selectedUser.department}</p>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-2">Last Login</h4>
                  <p className="text-slate-300">{selectedUser.lastLogin.toLocaleString()}</p>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-3">Permissions</h4>
                  <div className="space-y-2">
                    {(selectedUser.role === 'admin' ? ['Full System Access'] : rolePermissions[selectedUser.role]).map((permission) => (
                      <div key={permission} className="flex items-center space-x-2 px-3 py-2 bg-slate-700/50 rounded-lg">
                        <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                        <span className="text-slate-300">{permission.replace('_', ' ').toUpperCase()}</span>
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

export default UserRoles;