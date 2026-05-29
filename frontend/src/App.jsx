import React, { useState, useCallback, useMemo } from 'react';
import NetworkGraph from './components/NetworkGraph';
import DevicePanel from './components/DevicePanel';
import ScanControls from './components/ScanControls';
import TrustOverlay from './components/TrustOverlay';
import { useWebSocket } from './hooks/useWebSocket';

export default function App() {
  const { connected, progress, scanResult, error, startScan } = useWebSocket();
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [activeTab, setActiveTab] = useState('trust'); // 'trust' or 'scan'

  const handleStartScan = useCallback((network) => {
    setSelectedDevice(null);
    startScan(network);
  }, [startScan]);

  const handleDeviceSelect = useCallback((device) => {
    setSelectedDevice(device);
  }, []);

  // Find blast radius for selected device
  const selectedBlastRadius = useMemo(() => {
    if (!selectedDevice || !scanResult?.blast_radius_analyses) return null;
    return scanResult.blast_radius_analyses.find(
      (b) => b.device_ip === selectedDevice.ip
    ) || null;
  }, [selectedDevice, scanResult]);

  // Get connections for the graph
  const connections = useMemo(() => {
    if (!scanResult?.connections) return [];
    // Limit connections to avoid visual clutter
    const sorted = [...scanResult.connections].sort((a, b) => b.risk_score - a.risk_score);
    return sorted.slice(0, 200);
  }, [scanResult]);

  const trustAnalysis = scanResult?.zero_trust_analysis || null;

  return (
    <div className="app">
      {/* Header */}
      <header className="app-header">
        <div className="header-left">
          <div className="logo">
            <span className="logo-icon">⟐</span>
            <h1>ZTNM</h1>
          </div>
          <span className="header-subtitle">Zero-Trust Network Map</span>
        </div>
        <div className="header-right">
          <div className="header-stats">
            {scanResult && (
              <>
                <span className="stat">{scanResult.total_devices || 0} devices</span>
                <span className="stat-divider">|</span>
                <span className="stat">{scanResult.total_open_ports || 0} ports</span>
              </>
            )}
          </div>
          <span className={`status-badge ${connected ? 'online' : 'offline'}`}>
            {connected ? '● Online' : '○ Offline'}
          </span>
        </div>
      </header>

      {/* Main content */}
      <div className="app-body">
        {/* Left panel */}
        <aside className="left-panel">
          <div className="panel-tabs">
            <button
              className={`tab-btn ${activeTab === 'scan' ? 'active' : ''}`}
              onClick={() => setActiveTab('scan')}
            >
              Scanner
            </button>
            <button
              className={`tab-btn ${activeTab === 'trust' ? 'active' : ''}`}
              onClick={() => setActiveTab('trust')}
            >
              Zero-Trust
            </button>
          </div>

          <div className="panel-content">
            {activeTab === 'scan' ? (
              <ScanControls
                onStartScan={handleStartScan}
                scanResult={scanResult}
                progress={progress}
                connected={connected}
              />
            ) : (
              <TrustOverlay
                scanResult={scanResult}
                analysis={trustAnalysis}
              />
            )}
          </div>
        </aside>

        {/* Center: Network Graph */}
        <main className="center-panel">
          <NetworkGraph
            devices={scanResult?.devices || []}
            connections={connections}
            onDeviceSelect={handleDeviceSelect}
            selectedDevice={selectedDevice}
          />

          {/* Progress overlay when scanning */}
          {progress && progress.status !== 'completed' && progress.status !== 'failed' && (
            <div className="scanning-overlay">
              <div className="scanning-card">
                <div className="scanning-spinner" />
                <div className="scanning-text">{progress.message || 'Scanning network...'}</div>
                <div className="scanning-bar">
                  <div className="scanning-fill" style={{ width: `${progress.percent || 0}%` }} />
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="error-toast">
              <span>⚠</span> {error}
            </div>
          )}
        </main>

        {/* Right panel: Device details */}
        <aside className="right-panel">
          {selectedDevice ? (
            <DevicePanel
              device={selectedDevice}
              onClose={() => setSelectedDevice(null)}
              blastRadius={selectedBlastRadius}
            />
          ) : (
            <div className="right-placeholder">
              <div className="placeholder-icon">👆</div>
              <h3>Select a Device</h3>
              <p>Click on any node in the 3D network graph to see detailed information, services, and blast radius analysis.</p>
              <div className="placeholder-tips">
                <div className="tip">
                  <span className="tip-dot" style={{ background: '#00ff88' }} />
                  <span>Critical / High Trust</span>
                </div>
                <div className="tip">
                  <span className="tip-dot" style={{ background: '#ffaa00' }} />
                  <span>Medium Trust</span>
                </div>
                <div className="tip">
                  <span className="tip-dot" style={{ background: '#ff6600' }} />
                  <span>Low Trust</span>
                </div>
                <div className="tip">
                  <span className="tip-dot" style={{ background: '#ff2244' }} />
                  <span>Untrusted / High Risk</span>
                </div>
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
