import React, { useState, useEffect } from 'react';

export default function ScanControls({ onStartScan, scanResult, progress, connected }) {
  const [network, setNetwork] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/network-info')
      .then((r) => r.json())
      .then((data) => {
        setNetwork(data.network || '192.168.1.0/24');
        setLoading(false);
      })
      .catch(() => {
        setNetwork('192.168.1.0/24');
        setLoading(false);
      });
  }, []);

  const isValidPlainIP = (input) => {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(input)) return false;
    const octets = input.split('.').map(Number);
    return !octets.some((o) => o < 0 || o > 255);
  };

  const normalizeNetwork = (input) => {
    const trimmed = input.trim();
    if (isValidPlainIP(trimmed)) {
      return `${trimmed}/24`;
    }
    return trimmed;
  };

  const validateCIDR = (input) => {
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (!cidrRegex.test(input)) {
      if (isValidPlainIP(input)) return null; // will be normalized on submit
      return 'Enter a network like 192.168.1.0 (or 192.168.1.0/24 for a custom subnet)';
    }
    const [ip, bits] = input.split('/');
    const octets = ip.split('.').map(Number);
    if (octets.some((o) => o < 0 || o > 255)) return 'Invalid IP address';
    const prefix = parseInt(bits);
    if (prefix < 8 || prefix > 30) return 'Prefix must be between /8 and /30';
    return null;
  };

  const [validationError, setValidationError] = useState(null);

  const handleStart = () => {
    const normalized = normalizeNetwork(network);
    // Update the visible input to show the normalized value
    if (normalized !== network) {
      setNetwork(normalized);
    }
    const err = validateCIDR(normalized);
    if (err) {
      setValidationError(err);
      return;
    }
    setValidationError(null);
    if (onStartScan) onStartScan(normalized);
  };

  const isScanning = progress && (progress.status === 'running' || progress.status === 'starting' || progress.status === 'scanning');
  const scanComplete = scanResult && scanResult.scan_status === 'completed';
  const isFailed = progress?.status === 'failed';
  const scanPct = progress?.percent || 0;

  return (
    <div className="scan-controls">
      <div className="scan-header">
        <h3>Network Scanner</h3>
        <span className={`connection-status ${connected ? 'connected' : 'disconnected'}`}>
          {connected ? '● Connected' : '○ Reconnecting...'}
        </span>
      </div>

      <div className="scan-input-group">
        <label>Target Network</label>
        <div className="network-input-row">
          <input
            type="text"
            value={network}
            onChange={(e) => { setNetwork(e.target.value); setValidationError(null); }}
            placeholder="192.168.1.0/24"
            disabled={isScanning}
            className="network-input"
            aria-label="Target network CIDR"
            id="network-input"
          />
          <button
            className={`scan-btn ${isScanning ? 'scanning' : ''}`}
            onClick={handleStart}
            disabled={isScanning || loading}
          >
            {isScanning ? (
              <>
                <span className="scan-spinner" />
                Scanning...
              </>
            ) : (
              <>
                <span className="scan-icon">⟐</span>
                Start Scan
              </>
            )}
          </button>
        </div>
      </div>

      {/* Validation error */}
      {validationError && (
        <div className="scan-failed">
          <span className="failed-icon">⚠</span>
          {validationError}
        </div>
      )}

      {/* Progress bar */}
      {isScanning && (
        <div className="scan-progress">
          <div className="progress-bar">
            <div
              className="progress-fill"
              style={{ width: `${Math.max(scanPct, 5)}%` }}
            />
          </div>
          <div className="progress-info">
            <span className="progress-text">{progress?.message || 'Scanning...'}</span>
            <span className="progress-pct">{scanPct}%</span>
          </div>
        </div>
      )}

      {/* Failed message */}
      {isFailed && (
        <div className="scan-failed">
          <span className="failed-icon">⚠</span>
          {progress?.message || 'Scan failed'}
        </div>
      )}

      {/* Results summary */}
      {scanComplete && scanResult && (
        <div className="scan-result-summary">
          <div className="result-header">Scan Complete</div>
          <div className="result-stats">
            <div className="result-stat">
              <span className="rs-value">{scanResult.total_devices || 0}</span>
              <span className="rs-label">Devices</span>
            </div>
            <div className="result-stat">
              <span className="rs-value">{scanResult.total_open_ports || 0}</span>
              <span className="rs-label">Open Ports</span>
            </div>
            <div className="result-stat">
              <span className="rs-value">{scanResult.total_high_risk_devices || 0}</span>
              <span className="rs-label">High Risk</span>
            </div>
            <div className="result-stat">
              <span className="rs-value">{(scanResult.overall_risk_score * 100 || 0).toFixed(0)}%</span>
              <span className="rs-label">Risk Score</span>
            </div>
          </div>
          {scanResult.scan_duration_seconds && (
            <div className="scan-duration">
              Scan completed in {scanResult.scan_duration_seconds.toFixed(1)}s
            </div>
          )}
        </div>
      )}
    </div>
  );
}
