import { useState, useEffect } from 'react'
import { getReportsStats } from '../api'
import '../pages/Reports.css'

function Reports({ onNavigate }) {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchStats = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getReportsStats()
      setStats(data)
    } catch (err) {
      console.error('Failed to fetch reports stats:', err)
      setError(err.detail || 'Could not load reports statistics.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStats()
  }, [])

  const calcPercentage = (val, total) => {
    if (!total || total === 0) return 0
    return Math.round((val / total) * 100)
  }

  return (
    <div className="reports-page">
      <div className="reports-header">
        <div>
          <h2>Security Threat Reports & Analytics</h2>
          <p className="subtitle">Real-time aggregate data and risk metric distributions</p>
        </div>
        <button className="btn-secondary refresh-btn" onClick={fetchStats} disabled={loading}>
          🔄 {loading ? 'Refreshing...' : 'Refresh Stats'}
        </button>
      </div>

      {error && (
        <div className="error-box">
          <span className="error-icon">⚠️</span>
          <p>{error}</p>
        </div>
      )}

      {stats && !stats.mongodb_connected && (
        <div className="warning-banner">
          ⚠️ MongoDB is offline or MONGODB_URI is not set. Database analytics are in fallback mode (0 active records).
        </div>
      )}

      {loading ? (
        <div className="loading-box">
          <div className="spinner"></div>
          <p>Generating reports analytics...</p>
        </div>
      ) : (
        stats && (
          <div className="reports-content">
            {/* Metric Summary Cards */}
            <div className="stats-summary-grid">
              <div className="report-card metric-card">
                <div className="card-icon icon-blue">📊</div>
                <div className="metric-info">
                  <span className="metric-label">Total Scans</span>
                  <span className="metric-val">{stats.total_scans}</span>
                </div>
              </div>

              <div className="report-card metric-card">
                <div className="card-icon icon-green">🟢</div>
                <div className="metric-info">
                  <span className="metric-label">Safe Scans</span>
                  <span className="metric-val">{stats.verdicts?.SAFE ?? 0}</span>
                </div>
              </div>

              <div className="report-card metric-card">
                <div className="card-icon icon-orange">🟡</div>
                <div className="metric-info">
                  <span className="metric-label">Suspicious Threats</span>
                  <span className="metric-val">{stats.verdicts?.SUSPICIOUS ?? 0}</span>
                </div>
              </div>

              <div className="report-card metric-card">
                <div className="card-icon icon-red">🔴</div>
                <div className="metric-info">
                  <span className="metric-label">Fraud / Malicious</span>
                  <span className="metric-val">{stats.verdicts?.FRAUD ?? 0}</span>
                </div>
              </div>
            </div>

            {/* Detailed Visual Distribution Bars */}
            <div className="charts-grid">
              {/* Verdict Breakdown */}
              <div className="report-card chart-card">
                <h3>Verdict Breakdown</h3>
                <p className="card-subtitle">Classification of scanned items</p>
                <div className="bar-list">
                  {['SAFE', 'SUSPICIOUS', 'FRAUD'].map((key) => {
                    const count = stats.verdicts?.[key] ?? 0
                    const pct = calcPercentage(count, stats.total_scans)
                    const colorClass =
                      key === 'SAFE' ? 'bar-green' : key === 'SUSPICIOUS' ? 'bar-orange' : 'bar-red'
                    return (
                      <div key={key} className="bar-item">
                        <div className="bar-label-row">
                          <span className="bar-title">{key}</span>
                          <span className="bar-meta">
                            {count} ({pct}%)
                          </span>
                        </div>
                        <div className="bar-track">
                          <div
                            className={`bar-fill ${colorClass}`}
                            style={{ width: `${pct}%` }}
                          ></div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Risk Level Distribution */}
              <div className="report-card chart-card">
                <h3>Risk Level Distribution</h3>
                <p className="card-subtitle">Distribution across risk tiers</p>
                <div className="bar-list">
                  {[
                    { key: 'CRITICAL', color: 'bar-red' },
                    { key: 'HIGH', color: 'bar-orange' },
                    { key: 'MEDIUM', color: 'bar-yellow' },
                    { key: 'LOW', color: 'bar-green' },
                  ].map(({ key, color }) => {
                    const count = stats.risk_levels?.[key] ?? 0
                    const pct = calcPercentage(count, stats.total_scans)
                    return (
                      <div key={key} className="bar-item">
                        <div className="bar-label-row">
                          <span className="bar-title">{key} Risk</span>
                          <span className="bar-meta">
                            {count} ({pct}%)
                          </span>
                        </div>
                        <div className="bar-track">
                          <div
                            className={`bar-fill ${color}`}
                            style={{ width: `${pct}%` }}
                          ></div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Scan Type Breakdown */}
              <div className="report-card chart-card full-width-chart">
                <h3>Scan Activity by Asset Type</h3>
                <p className="card-subtitle">Comparison of Message, URL, and APK scans</p>
                <div className="bar-list">
                  {[
                    { key: 'message', label: '📧 Message Scans', color: 'bar-blue' },
                    { key: 'url', label: '🌐 URL Scans', color: 'bar-cyan' },
                    { key: 'apk', label: '📦 APK File Scans', color: 'bar-purple' },
                  ].map(({ key, label, color }) => {
                    const count = stats.by_type?.[key] ?? 0
                    const pct = calcPercentage(count, stats.total_scans)
                    return (
                      <div key={key} className="bar-item">
                        <div className="bar-label-row">
                          <span className="bar-title">{label}</span>
                          <span className="bar-meta">
                            {count} scans ({pct}%)
                          </span>
                        </div>
                        <div className="bar-track">
                          <div
                            className={`bar-fill ${color}`}
                            style={{ width: `${pct}%` }}
                          ></div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>

            <div className="reports-actions">
              <h3>Start a New Analysis</h3>
              <div className="action-buttons">
                <button className="action-btn" onClick={() => onNavigate('message')}>
                  📧 Analyze Message
                </button>
                <button className="action-btn" onClick={() => onNavigate('url')}>
                  🌐 Analyze URL
                </button>
                <button className="action-btn" onClick={() => onNavigate('apk')}>
                  📦 Analyze APK
                </button>
                <button className="action-btn" onClick={() => onNavigate('history')}>
                  📜 View History
                </button>
              </div>
            </div>
          </div>
        )
      )}
    </div>
  )
}

export default Reports
