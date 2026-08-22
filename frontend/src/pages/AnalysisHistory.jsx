import { useState, useEffect } from 'react'
import { getHistory } from '../api'
import '../pages/AnalysisHistory.css'

function AnalysisHistory({ onNavigate }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filterType, setFilterType] = useState('ALL')
  const [expandedId, setExpandedId] = useState(null)

  const fetchHistory = async () => {
    setLoading(true)
    setError(null)
    try {
      const typeParam = filterType === 'ALL' ? null : filterType.toLowerCase()
      const data = await getHistory(typeParam)
      setHistory(data || [])
    } catch (err) {
      console.error('Failed to fetch history:', err)
      setError(err.detail || 'Could not load analysis history.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [filterType])

  const getRiskBadgeClass = (riskLevel) => {
    switch (riskLevel?.toUpperCase()) {
      case 'CRITICAL':
        return 'badge-critical'
      case 'HIGH':
        return 'badge-high'
      case 'MEDIUM':
        return 'badge-medium'
      case 'LOW':
        return 'badge-low'
      default:
        return 'badge-low'
    }
  }

  const getTypeIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'message':
        return '📧'
      case 'url':
        return '🌐'
      case 'apk':
        return '📦'
      default:
        return '🔍'
    }
  }

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A'
    try {
      return new Date(timestamp).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    } catch (e) {
      return String(timestamp)
    }
  }

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id)
  }

  return (
    <div className="analysis-history">
      <div className="history-header">
        <div>
          <h2>Analysis History</h2>
          <p className="subtitle">View previous security scans recorded in MongoDB</p>
        </div>
        <button className="btn-secondary refresh-btn" onClick={fetchHistory} disabled={loading}>
          🔄 {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      <div className="history-filters">
        {['ALL', 'MESSAGE', 'URL', 'APK'].map((type) => (
          <button
            key={type}
            className={`filter-btn ${filterType === type ? 'active' : ''}`}
            onClick={() => setFilterType(type)}
          >
            {type === 'ALL' ? 'All Scans' : `${getTypeIcon(type)} ${type}`}
          </button>
        ))}
      </div>

      {error && (
        <div className="error-box">
          <span className="error-icon">⚠️</span>
          <p>{error}</p>
        </div>
      )}

      {loading ? (
        <div className="loading-box">
          <div className="spinner"></div>
          <p>Loading scan history...</p>
        </div>
      ) : history.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📂</div>
          <h3>No Analysis History Found</h3>
          <p>
            {filterType !== 'ALL'
              ? `No ${filterType.toLowerCase()} scans found.`
              : 'Either no scans have been performed yet, or MongoDB persistence is not configured.'}
          </p>
          <div className="empty-actions">
            <button className="analyze-btn" onClick={() => onNavigate('message')}>
              📧 Scan Message
            </button>
            <button className="analyze-btn" onClick={() => onNavigate('url')}>
              🌐 Scan URL
            </button>
            <button className="analyze-btn" onClick={() => onNavigate('apk')}>
              📦 Scan APK
            </button>
          </div>
        </div>
      ) : (
        <div className="table-container">
          <table className="history-table">
            <thead>
              <tr>
                <th>Analysis ID</th>
                <th>Timestamp</th>
                <th>Type</th>
                <th>Target Identifier</th>
                <th>Risk Level</th>
                <th>Risk Score</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item, index) => {
                const isExpanded = expandedId === (item.analysis_id || index)
                return (
                  <tr key={item.analysis_id || index} className={isExpanded ? 'expanded-row' : ''}>
                    <td colSpan={isExpanded ? 7 : 1}>
                      {!isExpanded ? (
                        <code>{item.analysis_id || 'N/A'}</code>
                      ) : (
                        <div className="row-expanded-container">
                          <div className="row-summary">
                            <div>
                              <strong>ID:</strong> <code>{item.analysis_id}</code>
                            </div>
                            <div>
                              <strong>Timestamp:</strong> {formatDate(item.timestamp)}
                            </div>
                            <div>
                              <strong>Type:</strong> {getTypeIcon(item.type)} {item.type?.toUpperCase()}
                            </div>
                            <div>
                              <strong>Risk Level:</strong>{' '}
                              <span className={`risk-badge ${getRiskBadgeClass(item.risk_level)}`}>
                                {item.risk_level}
                              </span>
                            </div>
                            <button className="btn-close-expand" onClick={() => toggleExpand(item.analysis_id || index)}>
                              ✖ Close Details
                            </button>
                          </div>

                          <div className="row-details">
                            {item.target && (
                              <div className="detail-field">
                                <label>Target:</label>
                                <code className="target-code">{item.target}</code>
                              </div>
                            )}
                            {item.category && (
                              <div className="detail-field">
                                <label>Category:</label>
                                <span>{item.category}</span>
                              </div>
                            )}
                            {item.verdict && (
                              <div className="detail-field">
                                <label>Verdict:</label>
                                <span>{item.verdict}</span>
                              </div>
                            )}
                            {item.reasons && item.reasons.length > 0 && (
                              <div className="detail-field full-width">
                                <label>Reasons:</label>
                                <ul>
                                  {item.reasons.map((r, i) => (
                                    <li key={i}>{r}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            {item.recommendation && (
                              <div className="detail-field full-width">
                                <label>Recommendation:</label>
                                <p className="recommendation-text">{item.recommendation}</p>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </td>
                    {!isExpanded && (
                      <>
                        <td>{formatDate(item.timestamp)}</td>
                        <td>
                          <span className="type-tag">
                            {getTypeIcon(item.type)} {item.type}
                          </span>
                        </td>
                        <td className="target-cell" title={item.target}>
                          <code>{item.target}</code>
                        </td>
                        <td>
                          <span className={`risk-badge ${getRiskBadgeClass(item.risk_level)}`}>
                            {item.risk_level}
                          </span>
                        </td>
                        <td>
                          <span className="score-num">{item.risk_score ?? 'N/A'}</span>
                        </td>
                        <td>
                          <button
                            className="btn-details"
                            onClick={() => toggleExpand(item.analysis_id || index)}
                          >
                            Details 👁️
                          </button>
                        </td>
                      </>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default AnalysisHistory
