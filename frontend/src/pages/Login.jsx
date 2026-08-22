import { useState } from 'react'
import { loginUser } from '../api'
import './Login.css'

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!username.trim() || !password.trim()) {
      setError('Please enter both username and password.')
      return
    }
    setLoading(true)
    try {
      const data = await loginUser(username.trim(), password.trim())
      // Persist session
      localStorage.setItem('ss_token',    data.access_token)
      localStorage.setItem('ss_username', data.username)
      localStorage.setItem('ss_role',     data.role)
      onLoginSuccess({ username: data.username, role: data.role })
    } catch (err) {
      setError(err?.detail || 'Invalid credentials. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const fillDemo = (user, pass) => {
    setUsername(user)
    setPassword(pass)
    setError(null)
  }

  return (
    <div className="login-page">
      <div className="login-card">
        {/* Brand */}
        <div className="login-brand">
          <span className="login-shield">🛡️</span>
          <h1>SafeShield</h1>
          <p>AI Cyber Risk Assistant</p>
        </div>

        <h2 className="login-title">Sign In</h2>

        {error && <div className="login-error" role="alert">{error}</div>}

        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              autoComplete="username"
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              autoComplete="current-password"
              disabled={loading}
            />
          </div>

          <button
            type="submit"
            className="login-btn"
            disabled={loading}
          >
            {loading ? 'Signing in\u2026' : 'Sign In \u2192'}
          </button>
        </form>

        {/* Quick-fill demo credential chips */}
        <div className="demo-section">
          <p className="demo-label">Demo credentials</p>
          <div className="demo-chips">
            <button
              type="button"
              className="demo-chip"
              onClick={() => fillDemo('admin', 'password123')}
            >
              admin / password123
            </button>
            <button
              type="button"
              className="demo-chip"
              onClick={() => fillDemo('analyst', 'safeshield2026')}
            >
              analyst / safeshield2026
            </button>
            <button
              type="button"
              className="demo-chip"
              onClick={() => fillDemo('demo', 'demo123')}
            >
              demo / demo123
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
