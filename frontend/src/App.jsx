import { useState, useEffect } from 'react'
import './App.css'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import MessageScanner from './pages/MessageScanner'
import URLScanner from './pages/URLScanner'
import ApkScanner from './pages/ApkScanner'
import AnalysisHistory from './pages/AnalysisHistory'
import Reports from './pages/Reports'
import { getHealth } from './api'

function App() {
  // ── Auth state (lazy-init from localStorage) ──────────────────────────────
  const [isAuthenticated, setIsAuthenticated] = useState(
    () => !!localStorage.getItem('ss_token')
  )
  const [currentUser, setCurrentUser] = useState(
    () => localStorage.getItem('ss_username') || null
  )

  // ── Navigation + backend state ─────────────────────────────────────────────
  const [currentPage, setCurrentPage] = useState('dashboard')
  const [backendConnected, setBackendConnected] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const checkBackend = async () => {
      try {
        await getHealth()
        setBackendConnected(true)
      } catch {
        setBackendConnected(false)
      } finally {
        setLoading(false)
      }
    }
    checkBackend()
  }, [])

  // ── Auth handlers ──────────────────────────────────────────────────────────
  const handleLoginSuccess = ({ username }) => {
    setIsAuthenticated(true)
    setCurrentUser(username)
    setCurrentPage('dashboard')
  }

  const handleLogout = () => {
    localStorage.removeItem('ss_token')
    localStorage.removeItem('ss_username')
    localStorage.removeItem('ss_role')
    setIsAuthenticated(false)
    setCurrentUser(null)
    setCurrentPage('dashboard')
  }

  // Route guard — unauthenticated users only see login
  const navigateTo = (page) => {
    if (!isAuthenticated) return
    setCurrentPage(page)
  }

  // ── Page renderer ──────────────────────────────────────────────────────────
  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':   return <Dashboard onNavigate={navigateTo} />
      case 'message':     return <MessageScanner onNavigate={navigateTo} />
      case 'url':         return <URLScanner onNavigate={navigateTo} />
      case 'apk':         return <ApkScanner onNavigate={navigateTo} />
      case 'history':     return <AnalysisHistory onNavigate={navigateTo} />
      case 'reports':     return <Reports onNavigate={navigateTo} />
      default:            return <Dashboard onNavigate={navigateTo} />
    }
  }

  // ── Loading splash ─────────────────────────────────────────────────────────
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

  // ── Unauthenticated: show only the login page ──────────────────────────────
  if (!isAuthenticated) {
    return <Login onLoginSuccess={handleLoginSuccess} />
  }

  // ── Authenticated shell ────────────────────────────────────────────────────
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
          <div className="header-actions">
            <div className="backend-status">
              {backendConnected ? (
                <span className="status-online">● Connected</span>
              ) : (
                <span className="status-offline">● Offline</span>
              )}
            </div>
            <div className="user-badge">
              <span className="user-icon">👤</span>
              <span className="user-name">{currentUser}</span>
            </div>
            <button className="logout-btn" onClick={handleLogout}>
              Sign Out
            </button>
          </div>
        </div>
      </header>

      <nav className="app-nav">
        <button
          className={`nav-btn ${currentPage === 'dashboard' ? 'active' : ''}`}
          onClick={() => navigateTo('dashboard')}
        >
          Dashboard
        </button>
        <button
          className={`nav-btn ${currentPage === 'message' ? 'active' : ''}`}
          onClick={() => navigateTo('message')}
        >
          Message Scanner
        </button>
        <button
          className={`nav-btn ${currentPage === 'url' ? 'active' : ''}`}
          onClick={() => navigateTo('url')}
        >
          URL Scanner
        </button>
        <button
          className={`nav-btn ${currentPage === 'image' ? 'active' : ''}`}
          onClick={() => navigateTo('image')}
          disabled
        >
          Image Scanner
        </button>
        <button
          className={`nav-btn ${currentPage === 'apk' ? 'active' : ''}`}
          onClick={() => navigateTo('apk')}
        >
          APK Scanner
        </button>
        <button
          className={`nav-btn ${currentPage === 'history' ? 'active' : ''}`}
          onClick={() => navigateTo('history')}
        >
          Analysis History
        </button>
        <button
          className={`nav-btn ${currentPage === 'reports' ? 'active' : ''}`}
          onClick={() => navigateTo('reports')}
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
