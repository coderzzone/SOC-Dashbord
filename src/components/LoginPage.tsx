import React, { useState } from 'react';
import { Shield, Eye, EyeOff, Lock, User, AlertCircle, CheckCircle } from 'lucide-react';

interface LoginPageProps {
  onLogin: (user: { id: string; name: string; email: string; role: 'soc_analyst' | 'incident_manager' | 'admin' }) => void;
}

interface LoginCredentials {
  email: string;
  password: string;
}

const LoginPage: React.FC<LoginPageProps> = ({ onLogin }) => {
  const [credentials, setCredentials] = useState<LoginCredentials>({
    email: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedDemo, setSelectedDemo] = useState<string>('');

  // Demo users for testing different roles
  const demoUsers = [
    {
      id: '1',
      name: 'John Doe',
      email: 'analyst@secops.com',
      password: 'analyst123',
      role: 'soc_analyst' as const,
      title: 'SOC Analyst'
    },
    {
      id: '2',
      name: 'Jane Smith',
      email: 'manager@secops.com',
      password: 'manager123',
      role: 'incident_manager' as const,
      title: 'Incident Manager'
    },
    {
      id: '3',
      name: 'Mike Johnson',
      email: 'admin@secops.com',
      password: 'admin123',
      role: 'admin' as const,
      title: 'System Administrator'
    }
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 1500));

    // Find matching user
    const user = demoUsers.find(u => 
      u.email === credentials.email && u.password === credentials.password
    );

    if (user) {
      onLogin({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      });
    } else {
      setError('Invalid email or password. Please try the demo credentials.');
    }

    setIsLoading(false);
  };

  const handleDemoLogin = (user: typeof demoUsers[0]) => {
    setCredentials({
      email: user.email,
      password: user.password
    });
    setSelectedDemo(user.role);
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin': return 'from-red-500 to-red-600 border-red-500/30';
      case 'incident_manager': return 'from-orange-500 to-orange-600 border-orange-500/30';
      case 'soc_analyst': return 'from-blue-500 to-blue-600 border-blue-500/30';
      default: return 'from-slate-500 to-slate-600 border-slate-500/30';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-10">
        <div className="absolute inset-0" style={{
          backgroundImage: `radial-gradient(circle at 25% 25%, #3b82f6 0%, transparent 50%),
                           radial-gradient(circle at 75% 75%, #8b5cf6 0%, transparent 50%)`
        }}></div>
      </div>

      <div className="relative w-full max-w-6xl">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
          {/* Left Side - Branding & Info */}
          <div className="text-center lg:text-left space-y-8">
            <div className="flex items-center justify-center lg:justify-start space-x-4">
              <div className="relative">
                <Shield className="w-16 h-16 text-blue-400" />
                <div className="absolute -top-1 -right-1 w-6 h-6 bg-green-400 rounded-full flex items-center justify-center">
                  <div className="w-2 h-2 bg-white rounded-full animate-pulse"></div>
                </div>
              </div>
              <div>
                <h1 className="text-4xl font-bold text-white">SecOps</h1>
                <p className="text-blue-400 font-medium">Security Operations Center</p>
              </div>
            </div>

            <div className="space-y-4">
              <h2 className="text-2xl font-bold text-white">
                Advanced Threat Detection & Response Platform
              </h2>
              <p className="text-slate-300 text-lg leading-relaxed">
                Monitor, analyze, and respond to security threats in real-time with our 
                comprehensive SOC dashboard. Built for security professionals who demand 
                precision and speed.
              </p>
            </div>

            {/* Features List */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {[
                { icon: Shield, text: 'Real-time Threat Detection' },
                { icon: AlertCircle, text: 'Incident Management' },
                { icon: CheckCircle, text: 'Automated Response' },
                { icon: User, text: 'Role-based Access' }
              ].map((feature, index) => (
                <div key={index} className="flex items-center space-x-3 text-slate-300">
                  <feature.icon className="w-5 h-5 text-blue-400 flex-shrink-0" />
                  <span>{feature.text}</span>
                </div>
              ))}
            </div>

            {/* Demo Credentials */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-6 border border-slate-700/50">
              <h3 className="text-white font-semibold mb-4 flex items-center">
                <Lock className="w-4 h-4 mr-2 text-blue-400" />
                Demo Credentials
              </h3>
              <div className="grid gap-3">
                {demoUsers.map((user) => (
                  <button
                    key={user.role}
                    onClick={() => handleDemoLogin(user)}
                    className={`p-3 rounded-lg border transition-all duration-200 text-left hover:scale-105 ${
                      selectedDemo === user.role 
                        ? `bg-gradient-to-r ${getRoleColor(user.role)} text-white shadow-lg` 
                        : 'bg-slate-700/30 border-slate-600/30 text-slate-300 hover:bg-slate-700/50'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-medium">{user.title}</div>
                        <div className="text-sm opacity-80">{user.email}</div>
                      </div>
                      <div className="text-xs opacity-60">
                        Click to use
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Right Side - Login Form */}
          <div className="flex justify-center lg:justify-end">
            <div className="w-full max-w-md">
              <div className="bg-slate-800/50 backdrop-blur-md rounded-2xl border border-slate-700/50 p-8 shadow-2xl">
                <div className="text-center mb-8">
                  <h3 className="text-2xl font-bold text-white mb-2">Welcome Back</h3>
                  <p className="text-slate-400">Sign in to access your SOC dashboard</p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-6">
                  {/* Email Field */}
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Email Address
                    </label>
                    <div className="relative">
                      <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
                      <input
                        type="email"
                        value={credentials.email}
                        onChange={(e) => setCredentials(prev => ({ ...prev, email: e.target.value }))}
                        className="w-full pl-10 pr-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                        placeholder="Enter your email"
                        required
                      />
                    </div>
                  </div>

                  {/* Password Field */}
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">
                      Password
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={credentials.password}
                        onChange={(e) => setCredentials(prev => ({ ...prev, password: e.target.value }))}
                        className="w-full pl-10 pr-12 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                        placeholder="Enter your password"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-white transition-colors"
                      >
                        {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                      </button>
                    </div>
                  </div>

                  {/* Error Message */}
                  {error && (
                    <div className="flex items-center space-x-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
                      <span className="text-red-400 text-sm">{error}</span>
                    </div>
                  )}

                  {/* Submit Button */}
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full py-3 px-4 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-medium rounded-lg transition-all duration-200 transform hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-800 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                  >
                    {isLoading ? (
                      <div className="flex items-center justify-center space-x-2">
                        <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                        <span>Authenticating...</span>
                      </div>
                    ) : (
                      'Sign In'
                    )}
                  </button>
                </form>

                {/* Security Notice */}
                <div className="mt-6 p-4 bg-slate-700/30 rounded-lg border border-slate-600/30">
                  <div className="flex items-start space-x-2">
                    <Shield className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                    <div className="text-xs text-slate-400">
                      <p className="font-medium text-slate-300 mb-1">Secure Authentication</p>
                      <p>Your session is protected with enterprise-grade security. All activities are logged and monitored.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;