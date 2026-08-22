import '../pages/Dashboard.css'

function Dashboard({ onNavigate }) {
  const stats = [
    { label: 'Total Analyses', value: '0', icon: '📊' },
    { label: 'Critical Threats', value: '0', icon: '🔴' },
    { label: 'High Risk', value: '0', icon: '🟠' },
    { label: 'Safe/Low Risk', value: '0', icon: '🟢' },
  ]

  return (
    <div className="dashboard">
      <h2>Dashboard</h2>

      <div className="stats-grid">
        {stats.map((stat, idx) => (
          <div key={idx} className="stat-card">
            <div className="stat-icon">{stat.icon}</div>
            <div className="stat-content">
              <p className="stat-label">{stat.label}</p>
              <p className="stat-value">{stat.value}</p>
            </div>
          </div>
        ))}
      </div>

      <section className="quick-actions">
        <h3>Quick Analysis</h3>
        <div className="action-buttons">
          <button className="action-btn" onClick={() => onNavigate('message')}>
            📧 Analyze Message
          </button>
          <button className="action-btn" onClick={() => onNavigate('url')}>
            🌐 Analyze URL
          </button>
          <button className="action-btn" onClick={() => onNavigate('image')}>
            🖼️ Analyze Image
          </button>
          <button className="action-btn" onClick={() => onNavigate('apk')}>
            📦 Analyze APK
          </button>
        </div>
      </section>

      <section className="recent-analyses">
        <h3>Recent Analyses</h3>
        <div className="empty-state">
          <p>No analyses yet. Start by scanning a message or URL.</p>
        </div>
      </section>
    </div>
  )
}

export default Dashboard
