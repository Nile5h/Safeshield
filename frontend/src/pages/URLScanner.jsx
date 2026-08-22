import { useState } from 'react'
import { analyzeUrl } from '../api'
import './MessageScanner.css'
import './URLScanner.css'

const riskClass = (riskLevel) => riskLevel?.toLowerCase() || 'low'

export default function URLScanner({ onNavigate }) {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleAnalyze = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to analyze')
      return
    }
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const data = await analyzeUrl(url)
      setResult(data)
    } catch (err) {
      setError(err?.detail || 'Failed to analyze URL. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const live = result?.live_inspection

  return (
    <div className="message-scanner">
      <div className="url-page-heading">
        <div>
          <p className="url-eyebrow">SafeShield URL protection</p>
          <h2>URL Scanner</h2>
        </div>
        <button className="btn-secondary" onClick={() => onNavigate('dashboard')}>
          Dashboard
        </button>
      </div>

      <div className="scanner-container">
        <div className="input-section">
          <label htmlFor="url-input">Paste a URL to inspect</label>
          <input
            id="url-input"
            type="url"
            placeholder="https://example.com/login"
            value={url}
            onChange={(event) => {
              setUrl(event.target.value)
              setError(null)
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter') handleAnalyze()
            }}
            disabled={loading}
          />
          <div className="input-footer">
            <span className="char-count">Live web crawler + ML classification</span>
            <button
              onClick={handleAnalyze}
              disabled={loading || !url.trim()}
              className="analyze-btn"
            >
              {loading ? 'Inspecting…' : 'Analyze URL'}
            </button>
          </div>
        </div>

        {error && (
          <div className="error-box">
            <span className="error-icon">⚠️</span>
            <p>{error}</p>
          </div>
        )}

        {loading && (
          <div className="loading-box">
            <div className="spinner"></div>
            <p>Fetching live headers, HTML & evaluating threat models…</p>
          </div>
        )}

        {result && !loading && (
          <div className="result-section">
            <div className="result-header">
              <h3>Analysis Result</h3>
              <span className={`risk-badge ${riskClass(result.risk_level)}`}>
                {result.verdict === 'FRAUD' ? '🔴' : '🟢'} {result.verdict} · {result.risk_level}
              </span>
            </div>

            {/* ── Real-Time Live Inspection & BeautifulSoup Telemetry ── */}
            {live && (
              <div className="live-telemetry-card">
                <div className="telemetry-header">
                  <div className="telemetry-title">
                    <span>🌐</span>
                    <span>Dynamic Website Inspection Telemetry</span>
                  </div>
                  {live.reachable ? (
                    <span className="telemetry-badge online">
                      ● Live Connected · HTTP {live.status_code || 200} ({live.response_time_ms}ms)
                    </span>
                  ) : live.attempted ? (
                    <span className="telemetry-badge offline">
                      ● Site Unreachable · ML Heuristic Fallback
                    </span>
                  ) : (
                    <span className="telemetry-badge bypass">
                      ● Whitelisted Domain (Fast-Path)
                    </span>
                  )}
                </div>

                <div className="telemetry-grid">
                  <div className="telemetry-stat">
                    <div className="telemetry-stat-label">Page Title</div>
                    <div className="telemetry-stat-value" title={live.page_title || 'N/A'}>
                      {live.page_title ? (live.page_title.length > 25 ? live.page_title.substring(0, 25) + '…' : live.page_title) : '—'}
                    </div>
                    <div className="telemetry-stat-sub">Parsed via BeautifulSoup</div>
                  </div>

                  <div className="telemetry-stat">
                    <div className="telemetry-stat-label">Forms & Passwords</div>
                    <div className="telemetry-stat-value">
                      {live.forms_count} forms / {live.password_inputs_count} pwd
                    </div>
                    <div className="telemetry-stat-sub">
                      {live.password_inputs_count > 0 ? 'Password input detected' : 'No credential fields'}
                    </div>
                  </div>

                  <div className="telemetry-stat">
                    <div className="telemetry-stat-label">Iframes Scanned</div>
                    <div className="telemetry-stat-value">
                      {live.iframes_count} ({live.hidden_iframes_count} hidden)
                    </div>
                    <div className="telemetry-stat-sub">
                      {live.hidden_iframes_count > 0 ? 'Covert zero-size iframe' : 'No covert iframes'}
                    </div>
                  </div>

                  <div className="telemetry-stat">
                    <div className="telemetry-stat-label">Links & Binaries</div>
                    <div className="telemetry-stat-value">
                      {live.links_checked_count} links / {live.executable_links_count} exe
                    </div>
                    <div className="telemetry-stat-sub">
                      {live.executable_links_count > 0 ? 'Executable payload link' : 'No drive-by payloads'}
                    </div>
                  </div>

                  <div className="telemetry-stat">
                    <div className="telemetry-stat-label">Server & Header</div>
                    <div className="telemetry-stat-value">
                      {live.server || (live.reachable ? 'Web Server' : 'N/A')}
                    </div>
                    <div className="telemetry-stat-sub">
                      {live.content_type ? (live.content_type.split(';')[0] || 'text/html') : 'N/A'}
                    </div>
                  </div>
                </div>

                {/* Real-time heuristic check chips */}
                <div className="telemetry-checks">
                  <div className="telemetry-checks-title">Dynamic Heuristic Verifications:</div>
                  <div className="check-chips">
                    <span className={`check-chip ${live.live_threats?.includes('credential_harvesting') ? 'warn' : 'pass'}`}>
                      {live.live_threats?.includes('credential_harvesting') ? '⚠️ Credential Harvesting Form' : '✓ Password Form Origin Safe'}
                    </span>
                    <span className={`check-chip ${live.live_threats?.includes('hidden_iframe') ? 'warn' : 'pass'}`}>
                      {live.live_threats?.includes('hidden_iframe') ? '⚠️ Covert / Hidden Iframe' : '✓ Zero-Size Iframes Clear'}
                    </span>
                    <span className={`check-chip ${live.live_threats?.includes('brand_title_mismatch') ? 'warn' : 'pass'}`}>
                      {live.live_threats?.includes('brand_title_mismatch') ? '⚠️ Deceptive Brand / Title' : '✓ Brand / Domain Match'}
                    </span>
                    <span className={`check-chip ${live.live_threats?.includes('drive_by_download_risk') || live.live_threats?.includes('malicious_content_type') ? 'warn' : 'pass'}`}>
                      {live.live_threats?.includes('drive_by_download_risk') || live.live_threats?.includes('malicious_content_type')
                        ? '⚠️ Executable Payload Link'
                        : '✓ Drive-By Payloads Clear'}
                    </span>
                  </div>
                  {live.fallback_reason && (
                    <p className="telemetry-fallback-note">
                      ℹ️ {live.fallback_reason}
                    </p>
                  )}
                </div>
              </div>
            )}

            <div className="analysis-details">
              <div className={`risk-score-card ${riskClass(result.risk_level)}`}>
                <div className="score-value">{result.risk_score}</div>
                <div className="score-label">Risk Score</div>
                <div className="score-scale">0-100</div>
              </div>

              <div className="details-grid">
                <div className="detail-item full-width">
                  <span className="detail-label">Normalized URL</span>
                  <code>{result.normalized_url}</code>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Category</span>
                  <p>{result.category}</p>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Confidence</span>
                  <p>{result.confidence}%</p>
                </div>

                <div className="detail-item">
                  <span className="detail-label">ML Model Confidence</span>
                  <p>{result.model_confidence}%</p>
                </div>

                <div className="detail-item">
                  <span className="detail-label">Static Rules Confidence</span>
                  <p>{result.rule_confidence}%</p>
                </div>

                <div className="detail-item full-width">
                  <span className="detail-label">Findings & Indicators</span>
                  <div className="reasons-list">
                    {result.reasons?.length ? (
                      <ul>
                        {result.reasons.map((reason) => (
                          <li key={reason}>{reason}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="no-reasons">No suspicious indicators detected.</p>
                    )}
                  </div>
                </div>

                <div className="detail-item full-width">
                  <span className="detail-label">Recommendation</span>
                  <div className="recommendation-box">
                    <p>{result.recommendation}</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="result-actions">
              <button onClick={() => setResult(null)} className="btn-secondary">
                Analyze Another URL
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
