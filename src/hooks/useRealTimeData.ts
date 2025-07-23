import { useState, useEffect, useCallback } from 'react';
import wsService from '../services/websocket';
import apiClient from '../services/api';

interface UseRealTimeDataOptions {
  enabled?: boolean;
  reconnectOnError?: boolean;
  maxRetries?: number;
}

export function useRealTimeData<T>(
  dataType: string,
  initialData: T[] = [],
  options: UseRealTimeDataOptions = {}
) {
  const [data, setData] = useState<T[]>(initialData);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);

  const { enabled = true, reconnectOnError = true, maxRetries = 3 } = options;

  const handleNewData = useCallback((newItem: T) => {
    setData(prevData => [newItem, ...prevData].slice(0, 1000)); // Keep latest 1000 items
  }, []);

  const handleConnectionChange = useCallback((status: { status: string }) => {
    setIsConnected(status.status === 'connected');
    if (status.status === 'connected') {
      setError(null);
      setRetryCount(0);
    }
  }, []);

  const handleError = useCallback((errorData: { error: any }) => {
    setError(errorData.error?.message || 'Connection error');
    setIsConnected(false);
    
    if (reconnectOnError && retryCount < maxRetries) {
      setTimeout(() => {
        setRetryCount(prev => prev + 1);
        wsService.connect();
      }, 5000 * (retryCount + 1)); // Exponential backoff
    }
  }, [reconnectOnError, retryCount, maxRetries]);

  useEffect(() => {
    if (!enabled) return;

    // Subscribe to WebSocket events
    wsService.subscribe(dataType, handleNewData);
    wsService.subscribe('connection', handleConnectionChange);
    wsService.subscribe('error', handleError);

    // Connect if not already connected
    if (!wsService.getConnectionStatus()) {
      const token = localStorage.getItem('auth_token');
      wsService.connect(token || undefined);
    }

    return () => {
      wsService.unsubscribe(dataType, handleNewData);
      wsService.unsubscribe('connection', handleConnectionChange);
      wsService.unsubscribe('error', handleError);
    };
  }, [enabled, dataType, handleNewData, handleConnectionChange, handleError]);

  const refresh = useCallback(async () => {
    try {
      // Fetch latest data from API as fallback
      const response = await apiClient.getAlerts({ limit: 50 });
      setData(response.data || []);
    } catch (err) {
      console.error('Failed to refresh data:', err);
    }
  }, []);

  return {
    data,
    isConnected,
    error,
    refresh,
    retryCount,
  };
}