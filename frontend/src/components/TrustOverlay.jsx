import React from 'react';

const SEVERITY_COLORS = {
  critical: { bg: '#ff224420', border: '#ff2244', text: '#ff2244', icon: '🔴' },
  high: { bg: '#ff660020', border: '#ff6600', text: '#ff6600', icon: '🟠' },
  medium: { bg: '#ffaa0020', border: '#ffaa00', text: '#ffaa00', icon: '🟡' },
  low: { bg: '#44aaff20', border: '#44aaff', text: '#44aaff', icon: '🔵' },
};

const TRUST_LEVEL_STYLES = {
  critical: { text: '#00ff88', border: '#00ff88' },
  high: { text: '#44aaff', border: '#44aaff' },
  medium: { text: '#ffaa00', border: '#ffaa00' },
  low: { text: '#ff6600', border: '#ff6600' },
  untrusted: { text: '#ff2244', border: '#ff2244' },
};

function ComplianceGauge({ score }) {
  const radius = 50;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? '#00ff88' : score >= 60 ? '#ffaa00' : score >= 40 ? '#ff6600' : '#ff2244';

  return (
    <div className="compliance-gauge">
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle
          cx="60" cy="60" r={radius}
          fill="none"
          stroke="#1a1a3a"
          strokeWidth="8"
        />
        <circle
          cx="60" cy="60" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 60 60)"
          style={{ transition: 'stroke-dashoffset 1s ease' }}
        />
        <text x="60" y="55" textAnchor="middle" fill="#fff" fontSize="22" fontWeight="700" fontFamily="JetBrains Mono, monospace">
          {score.toFixed(0)}
        </text>
        <text x="60" y="72" textAnchor="middle" fill={color} fontSize="10" fontWeight="500" fontFamily="Inter, sans-serif">
          /100
        </text>
      </svg>
      <div className="gauge-label" style={{ color }}>
        {score >= 80 ? 'Good' : score >= 60 ? 'Fair' : score >= 40 ? 'Poor' : 'Critical'}
      </div>
    </div>
  );
}

function FindingItem({ finding }) {
  const sc = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.medium;
  return (
    <div className="finding-item" style={{ background: sc.bg, borderLeft: `3px solid ${sc.border}` }}>
      <div className="finding-header">
        <span className="finding-severity" style={{ color: sc.text }}>
          {sc.icon} {finding.severity.toUpperCase()}
        </span>
        <span className="finding-type">{finding.type.replace(/_/g, ' ')}</span>
      </div>
      <p className="finding-message">{finding.message}</p>
    </div>
  );
}

function RecommendationItem({ recommendation }) {
  const priorityColors = {
    critical: { color: '#ff2244', label: 'CRITICAL' },
    high: { color: '#ff6600', label: 'HIGH' },
    medium: { color: '#ffaa00', label: 'MEDIUM' },
    low: { color: '#44aaff', label: 'LOW' },
  };
  const pc = priorityColors[recommendation.priority] || priorityColors.medium;

  return (
    <div className="recommendation-item">
      <div className="rec-header">
        <span className="rec-priority" style={{ borderColor: pc.color, color: pc.color }}>
          {pc.label}
        </span>
        <span className="rec-category">{recommendation.category?.replace(/_/g, ' ')}</span>
      </div>
      <p className="rec-message">{recommendation.message}</p>
    </div>
  );
}

export default function TrustOverlay({ scanResult, analysis }) {
  if (!analysis) {
    return (
      <div className="trust-overlay">
        <div className="overlay-placeholder">
          <div className="placeholder-icon">🛡️</div>
          <h3>Zero-Trust Analysis</h3>
          <p>Run a network scan to see the zero-trust security posture analysis.</p>
        </div>
      </div>
    );
  }

  const criticalFindings = analysis.findings?.filter((f) => f.severity === 'critical') || [];
  const highFindings = analysis.findings?.filter((f) => f.severity === 'high') || [];
  const otherFindings = analysis.findings?.filter((f) => !['critical', 'high'].includes(f.severity)) || [];

  return (
    <div className="trust-overlay">
      <div className="overlay-section">
        <h3>Compliance Score</h3>
        <ComplianceGauge score={analysis.overall_compliance_score || 0} />
      </div>

      <div className="overlay-section">
        <h3>Trust Distribution</h3>
        <div className="trust-distribution">
          {analysis.trust_level_distribution && Object.entries(analysis.trust_level_distribution).map(([level, count]) => {
            if (count === 0) return null;
            const tc = TRUST_LEVEL_STYLES[level] || TRUST_LEVEL_STYLES.untrusted;
            const total = Object.values(analysis.trust_level_distribution).reduce((a, b) => a + b, 0);
            const pct = total > 0 ? (count / total) * 100 : 0;
            return (
              <div key={level} className="trust-bar-item">
                <div className="trust-bar-label">
                  <span style={{ color: tc.text }}>{level}</span>
                  <span>{count} devices</span>
                </div>
                <div className="trust-bar-bg">
                  <div
                    className="trust-bar-fill"
                    style={{ width: `${pct}%`, background: tc.border }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {criticalFindings.length > 0 && (
        <div className="overlay-section">
          <h3 className="section-danger">Critical Findings ({criticalFindings.length})</h3>
          {criticalFindings.map((f, i) => (
            <FindingItem key={`critical-${i}`} finding={f} />
          ))}
        </div>
      )}

      {highFindings.length > 0 && (
        <div className="overlay-section">
          <h3 className="section-warning">High Severity ({highFindings.length})</h3>
          {highFindings.map((f, i) => (
            <FindingItem key={`high-${i}`} finding={f} />
          ))}
        </div>
      )}

      {analysis.recommendations && analysis.recommendations.length > 0 && (
        <div className="overlay-section">
          <h3>Recommendations ({analysis.recommendations.length})</h3>
          <div className="recommendations-list">
            {analysis.recommendations.map((r, i) => (
              <RecommendationItem key={`rec-${i}`} recommendation={r} />
            ))}
          </div>
        </div>
      )}

      {analysis.summary && (
        <div className="overlay-section">
          <h3>Summary</h3>
          <pre className="analysis-summary">{analysis.summary}</pre>
        </div>
      )}
    </div>
  );
}

