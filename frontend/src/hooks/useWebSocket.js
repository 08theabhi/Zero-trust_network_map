import { useState, useEffect, useRef, useCallback } from 'react';

// Connect via Vite proxy in dev, or directly to 8000 in production
const WS_URL = `ws://${window.location.host}/ws`;

export function useWebSocket() {
  const [connected, setConnected] = useState(false);
  const [progress, setProgress] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        setConnected(true);
        setError(null);
        // Send ping to verify connection
        ws.send(JSON.stringify({ action: 'ping' }));
      };

      ws.onclose = () => {
        setConnected(false);
        // Auto-reconnect after 3s
        reconnectTimerRef.current = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        setError('WebSocket connection error');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === 'pong') {
            return;
          }

          if (data.type === 'scan_progress') {
            setProgress({
              status: data.status,
              percent: data.percent,
              message: data.message,
            });
          }

          if (data.type === 'scan_complete') {
            setScanResult(data.result);
            setProgress(null);
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e);
        }
      };

      wsRef.current = ws;
    } catch (e) {
      setError('Failed to create WebSocket connection');
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  const startScan = useCallback(async (network) => {
    setScanResult(null);
    setProgress({ status: 'starting', percent: 0, message: 'Starting scan...' });

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ network: network || null }),
      });

      if (!response.ok) {
        throw new Error('Failed to start scan');
      }

      return await response.json();
    } catch (e) {
      setError(e.message);
      setProgress(null);
      return null;
    }
  }, []);

  return {
    connected,
    progress,
    scanResult,
    error,
    startScan,
  };
}
