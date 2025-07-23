import React, { useState } from 'react';
import Dashboard from './components/Dashboard';
import LoginPage from './components/LoginPage';

interface User {
  id: string;
  name: string;
  email: string;
  role: 'soc_analyst' | 'incident_manager' | 'admin';
}

function App() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const handleLogin = (user: User) => {
    setCurrentUser(user);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setIsAuthenticated(false);
  };

  if (!isAuthenticated || !currentUser) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return (
    <div className="App">
      <Dashboard currentUser={currentUser} onLogout={handleLogout} />
    </div>
  );
}

export default App;