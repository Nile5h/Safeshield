import { useState, useRef } from 'react'
import { analyzeImage } from '../api'
import './ImageScanner.css'

function ImageScanner({ onNavigate }) {
  const [file, setFile] = useState(null)
  const [previewUrl, setPreviewUrl] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [isDragging, setIsDragging] = useState(false)
  const fileInputRef = useRef(null)

  const handleFileSelect = (selectedFile) => {
    if (!selectedFile) return

    const validTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/bmp']
    const validExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.bmp']
    const hasValidExt = validExtensions.some((ext) =>
      selectedFile.name.toLowerCase().endsWith(ext)
    )

    if (!validTypes.includes(selectedFile.type) && !hasValidExt) {
      setError('Please select a valid image file (PNG, JPEG, WEBP, BMP).')
      return
    }

    setFile(selectedFile)
    setError('')
    setResult(null)

    // Generate local preview URL
    const url = URL.createObjectURL(selectedFile)
    setPreviewUrl(url)
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    setIsDragging(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0])
    }
  }

  const handleClear = () => {
    setFile(null)
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl)
      setPreviewUrl(null)
    }
    setResult(null)
    setError('')
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select an image file to analyze.')
      return
    }

    setLoading(true)
    setError('')
    setResult(null)

    try {
      const response = await analyzeImage(file)
      setResult(response)
    } catch (err) {
      setError(err.detail || err.message || 'Image analysis failed. Please try again.')
      console.error('Image analysis error:', err)
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (riskLevel) => {
    switch (riskLevel?.toUpperCase()) {
      case 'CRITICAL':
        return 'critical'
      case 'HIGH':
        return 'high'
      case 'MEDIUM':
        return 'medium'
      case 'LOW':
        return 'low'
      default:
        return 'low'
    }
  }

  const getRiskIcon = (riskLevel) => {
    switch (riskLevel?.toUpperCase()) {
      case 'CRITICAL':
        return '🔴'
      case 'HIGH':
        return '🟠'
      case 'MEDIUM':
        return '🟡'
      case 'LOW':
        return '🟢'
      default:
        return '⚪'
    }
  }

  const formatFileSize = (bytes) => {
    if (!bytes) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
  }

  return (
    <div className="image-scanner">
      <div className="scanner-header">
        <h2>Image & QR Code Scanner</h2>
        <p className="scanner-subtitle">
          Extract OCR text and decode QR codes from screenshots, posters, and SMS to detect cyber threats.
        </p>
      </div>

      <div className="scanner-container">
        {/* Upload Box */}
        <div className="image-upload-card">
          <div
            className={`dropzone ${isDragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => !file && fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/webp,image/bmp"
              className="file-input-hidden"
              onChange={(e) => handleFileSelect(e.target.files?.[0])}
            />

            {!file ? (
              <div className="dropzone-prompt">
                <div className="upload-icon">🖼️</div>
                <h3>Drag & Drop Image Here</h3>
                <p>or click to browse files from your device</p>
                <div className="format-tags">
                  <span className="tag">PNG</span>
                  <span className="tag">JPG</span>
                  <span className="tag">JPEG</span>
                  <span className="tag">WEBP</span>
                </div>
              </div>
            ) : (
              <div className="preview-container">
                <div className="image-preview-wrapper">
                  <img src={previewUrl} alt="Upload preview" className="image-preview" />
                </div>
                <div className="file-info-bar">
                  <div className="file-meta">
                    <span className="file-name">{file.name}</span>
                    <span className="file-size">{formatFileSize(file.size)}</span>
                  </div>
                  <button
                    type="button"
                    className="btn-remove-file"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleClear()
                    }}
                    disabled={loading}
                  >
                    ✖ Remove
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="scanner-actions">
            <button
              className="analyze-btn"
              onClick={handleAnalyze}
              disabled={loading || !file}
            >
              {loading ? (
                <>
                  <span className="spinner-small"></span> Analyzing Image...
                </>
              ) : (
                '🔍 Analyze Image'
              )}
            </button>
            <button className="btn-secondary" onClick={() => onNavigate('dashboard')}>
              Back to Dashboard
            </button>
          </div>
        </div>

        {/* Error Box */}
        {error && (
          <div className="error-box">
            <span className="error-icon">⚠️</span>
            <p>{error}</p>
          </div>
        )}

        {/* Loading Box */}
        {loading && (
          <div className="loading-box">
            <div className="spinner"></div>
            <p>Decoding QR codes, extracting OCR text, and analyzing risk signals...</p>
          </div>
        )}

        {/* Results Section */}
        {result && !loading && (
          <div className="result-section">
            <div className="result-header">
              <div>
                <h3>Image Analysis Verdict</h3>
                <span className="analysis-id-badge">ID: {result.analysis_id}</span>
              </div>
              <span className={`risk-badge ${getRiskColor(result.risk_level)}`}>
                {getRiskIcon(result.risk_level)} {result.risk_level} RISK
              </span>
            </div>

            {/* Score & Summary Grid */}
            <div className="score-summary-grid">
              <div className={`risk-score-card ${getRiskColor(result.risk_level)}`}>
                <div className="score-value">{result.risk_score}</div>
                <div className="score-label">Combined Risk Score</div>
                <div className="score-scale">Scale: 0 - 100</div>
              </div>

              <div className="summary-overview-card">
                <div className="overview-row">
                  <span className="overview-label">Verdict:</span>
                  <span className={`verdict-text ${result.verdict === 'FRAUD' ? 'text-red' : result.verdict === 'SUSPICIOUS' ? 'text-yellow' : 'text-green'}`}>
                    {result.verdict}
                  </span>
                </div>
                <div className="overview-row">
                  <span className="overview-label">Classification:</span>
                  <span className="overview-value capitalize">{result.category?.replace(/_/g, ' ')}</span>
                </div>
                <div className="overview-row">
                  <span className="overview-label">Analysis Confidence:</span>
                  <span className="overview-value">{result.confidence}%</span>
                </div>
                <div className="overview-row">
                  <span className="overview-label">QR Codes Decoded:</span>
                  <span className="overview-value">{result.qr_codes?.length || 0}</span>
                </div>
                <div className="overview-row">
                  <span className="overview-label">URLs Identified:</span>
                  <span className="overview-value">{result.extracted_urls?.length || 0}</span>
                </div>
              </div>
            </div>

            {/* Decoded QR Codes & URLs Section */}
            {result.extracted_urls?.length > 0 && (
              <div className="detail-card-section">
                <h4>🌐 Decoded QR Codes & Extracted URLs</h4>
                <div className="url-results-list">
                  {result.url_analyses?.length > 0 ? (
                    result.url_analyses.map((urlItem, idx) => (
                      <div key={idx} className="url-item-card">
                        <div className="url-header-row">
                          <code className="url-link">{urlItem.original_url}</code>
                          <span className={`risk-badge-sm ${getRiskColor(urlItem.risk_level)}`}>
                            {urlItem.verdict || urlItem.risk_level} ({urlItem.risk_score}/100)
                          </span>
                        </div>
                        {urlItem.reasons?.length > 0 && (
                          <ul className="sub-reasons-list">
                            {urlItem.reasons.map((r, rIdx) => (
                              <li key={rIdx}>{r}</li>
                            ))}
                          </ul>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="raw-urls-list">
                      {result.extracted_urls.map((u, idx) => (
                        <div key={idx} className="raw-url-item">
                          <code>{u}</code>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Extracted OCR Text Section */}
            {result.extracted_text ? (
              <div className="detail-card-section">
                <h4>📝 Extracted OCR Text Content</h4>
                <div className="ocr-text-box">
                  <pre>{result.extracted_text}</pre>
                </div>
                {result.message_analysis && (
                  <div className="message-subanalysis">
                    <div className="subanalysis-header">
                      <span>Message Risk Score: <strong>{result.message_analysis.risk_score}/100</strong></span>
                      <span className={`badge-pill ${getRiskColor(result.message_analysis.risk_level)}`}>
                        {result.message_analysis.risk_level}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="detail-card-section empty-ocr-section">
                <h4>📝 OCR Text Extraction</h4>
                <p className="subtext-muted">
                  {result.ocr_status === 'tesseract_not_installed'
                    ? 'ℹ️ Tesseract OCR engine is not installed on the host. QR code analysis was completed.'
                    : 'No readable text content was detected in this image.'}
                </p>
              </div>
            )}

            {/* Detected Indicators and Reasons */}
            <div className="detail-card-section">
              <h4>⚠️ Why was this score assigned?</h4>
              {result.reasons?.length > 0 ? (
                <ul className="reasons-list">
                  {result.reasons.map((reason, idx) => (
                    <li key={idx}>{reason}</li>
                  ))}
                </ul>
              ) : (
                <p className="no-threats-msg">No suspicious threats detected.</p>
              )}

              {result.detected_indicators?.length > 0 && (
                <div className="indicators-group">
                  <label>Detected Indicators:</label>
                  <div className="indicator-tags">
                    {result.detected_indicators.map((ind, idx) => (
                      <span key={idx} className="indicator-tag">
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Recommendation Box */}
            <div className="detail-card-section recommendation-card">
              <h4>🛡️ Recommended Action</h4>
              <p className="recommendation-text">{result.recommendation}</p>
            </div>

            {/* Bottom Actions */}
            <div className="result-actions">
              <button onClick={handleClear} className="btn-secondary">
                🔄 Scan Another Image
              </button>
              <button className="btn-secondary" onClick={() => onNavigate('history')}>
                📜 View in History
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ImageScanner
