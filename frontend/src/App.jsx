import { useState, useEffect } from 'react'
import './App.css'
import Dashboard from './pages/Dashboard'
import MessageScanner from './pages/MessageScanner'
import URLScanner from './pages/URLScanner'
import ApkScanner from './pages/ApkScanner'
import AnalysisHistory from './pages/AnalysisHistory'
import Reports from './pages/Reports'
import { getHealth } from './api'

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard')
  const [backendConnected, setBackendConnected] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check backend connection on mount
    const checkBackend = async () => {
      try {
        await getHealth()
        setBackendConnected(true)
      } catch (error) {
        console.error('Backend connection failed:', error)
        setBackendConnected(false)
      } finally {
        setLoading(false)
      }
    }

    checkBackend()
  }, [])

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard onNavigate={setCurrentPage} />
      case 'message':
        return <MessageScanner onNavigate={setCurrentPage} />
      case 'url':
        return <URLScanner onNavigate={setCurrentPage} />
      case 'apk':
        return <ApkScanner onNavigate={setCurrentPage} />
      case 'history':
        return <AnalysisHistory onNavigate={setCurrentPage} />
      case 'reports':
        return <Reports onNavigate={setCurrentPage} />
      default:
        return <Dashboard onNavigate={setCurrentPage} />
    }
  }

  if (loading) {
    return (
      <div className="app-container">
        <div className="loading-screen">
          <div className="spinner"></div>
          <p>Connecting to SafeShield...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="header-content">
          <div className="logo-section">
            <div className="logo">🛡️</div>
            <div className="brand">
              <h1>SafeShield</h1>
              <p>AI Cyber Risk Assistant</p>
            </div>
          </div>
          <div className="backend-status">
            {backendConnected ? (
              <span className="status-online">● Connected</span>
            ) : (
              <span className="status-offline">● Offline</span>
            )}
          </div>
        </div>
      </header>

      <nav className="app-nav">
        <button
          className={`nav-btn ${currentPage === 'dashboard' ? 'active' : ''}`}
          onClick={() => setCurrentPage('dashboard')}
        >
          Dashboard
        </button>
        <button
          className={`nav-btn ${currentPage === 'message' ? 'active' : ''}`}
          onClick={() => setCurrentPage('message')}
        >
          Message Scanner
        </button>
        <button
          className={`nav-btn ${currentPage === 'url' ? 'active' : ''}`}
          onClick={() => setCurrentPage('url')}
        >
          URL Scanner
        </button>
        <button
          className={`nav-btn ${currentPage === 'image' ? 'active' : ''}`}
          onClick={() => setCurrentPage('image')}
          disabled
        >
          Image Scanner
        </button>
        <button
          className={`nav-btn ${currentPage === 'apk' ? 'active' : ''}`}
          onClick={() => setCurrentPage('apk')}
        >
          APK Scanner
        </button>
        <button
          className={`nav-btn ${currentPage === 'history' ? 'active' : ''}`}
          onClick={() => setCurrentPage('history')}
        >
          Analysis History
        </button>
        <button
          className={`nav-btn ${currentPage === 'reports' ? 'active' : ''}`}
          onClick={() => setCurrentPage('reports')}
        >
          Reports
        </button>
      </nav>

      <main className="app-main">
        {!backendConnected && (
          <div className="error-banner">
            ⚠️ Backend not connected. Please ensure the FastAPI server is running on http://127.0.0.1:8000
          </div>
        )}
        {renderPage()}
      </main>
    </div>
  )
}

export default App
