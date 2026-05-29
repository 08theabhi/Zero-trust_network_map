import React from 'react';

const TRUST_COLORS = {
  critical: { bg: '#00ff8820', border: '#00ff88', text: '#00ff88' },
  high: { bg: '#44aaff20', border: '#44aaff', text: '#44aaff' },
  medium: { bg: '#ffaa0020', border: '#ffaa00', text: '#ffaa00' },
  low: { bg: '#ff660020', border: '#ff6600', text: '#ff6600' },
  untrusted: { bg: '#ff224420', border: '#ff2244', text: '#ff2244' },
};

function RiskBar({ score }) {
  const percent = Math.min(score * 100, 100);
  const color = score > 0.7 ? '#ff2244' : score > 0.4 ? '#ffaa00' : '#00ff88';
  return (
    <div className="risk-bar">
      <div className="risk-bar-fill" style={{ width: `${percent}%`, background: color }} />
      <span className="risk-bar-label" style={{ color }}>{(score * 100).toFixed(0)}%</span>
    </div>
  );
}

function ServiceTag({ service }) {
  const color = service.risk_score > 0.6 ? '#ff2244' : service.risk_score > 0.3 ? '#ffaa00' : '#44aaff';
  return (
    <span className="service-tag" style={{ borderColor: color, color }}>
      {service.name} <span className="service-port">:{service.port}</span>
    </span>
  );
}

export default function DevicePanel({ device, onClose, blastRadius }) {
  if (!device) return null;

  const tc = TRUST_COLORS[device.trust_level] || TRUST_COLORS.untrusted;

  return (
    <div className="device-panel">
      <div className="device-panel-header" style={{ borderBottom: `2px solid ${tc.border}` }}>
        <div className="device-panel-title">
          <span className="device-status-dot" style={{ background: tc.text }} />
          <h3>{device.hostname}</h3>
        </div>
        <button className="panel-close-btn" onClick={onClose}>✕</button>
      </div>

      <div className="device-panel-body">
        <div className="device-info-grid">
          <div className="info-item">
            <label>IP Address</label>
            <span className="mono">{device.ip}</span>
          </div>
          <div className="info-item">
            <label>MAC Address</label>
            <span className="mono">{device.mac}</span>
          </div>
          <div className="info-item">
            <label>Vendor</label>
            <span>{device.vendor}</span>
          </div>
          <div className="info-item">
            <label>OS</label>
            <span>{device.os}</span>
          </div>
          <div className="info-item">
            <label>Device Type</label>
            <span>{device.device_type}</span>
          </div>
          <div className="info-item">
            <label>Trust Level</label>
            <span style={{ color: tc.text, fontWeight: 600 }}>{device.trust_level.toUpperCase()}</span>
          </div>
        </div>

        <div className="device-section">
          <h4>Risk Score</h4>
          <RiskBar score={device.risk_score} />
        </div>

        <div className="device-section">
          <h4>Open Ports & Services ({device.open_port_count})</h4>
          <div className="service-list">
            {device.services && device.services.length > 0 ? (
              device.services.map((svc, i) => (
                <ServiceTag key={i} service={svc} />
              ))
            ) : (
              <span className="no-data">No open ports detected</span>
            )}
          </div>
        </div>

        {blastRadius && (
          <div className="device-section">
            <h4>
              Blast Radius Analysis
              <span className={`severity-badge ${blastRadius.severity}`}>
                {blastRadius.severity.toUpperCase()}
              </span>
            </h4>
            <div className="blast-stats">
              <div className="stat-item">
                <span className="stat-value">{blastRadius.directly_exposed_ips?.length || 0}</span>
                <span className="stat-label">Direct</span>
              </div>
              <div className="stat-item">
                <span className="stat-value">{blastRadius.indirectly_exposed_ips?.length || 0}</span>
                <span className="stat-label">Indirect</span>
              </div>
              <div className="stat-item">
                <span className="stat-value">{blastRadius.total_exposed_devices || 0}</span>
                <span className="stat-label">Total Exposed</span>
              </div>
              <div className="stat-item">
                <span className="stat-value">{blastRadius.critical_data_risk ? '⚠️' : '✓'}</span>
                <span className="stat-label">Data Risk</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
