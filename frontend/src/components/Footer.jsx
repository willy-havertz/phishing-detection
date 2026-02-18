function Footer() {
  return (
    <footer className="footer">
      <div className="footer-content">
        <div className="footer-main">
          <span className="footer-brand"><i className="fas fa-shield-alt" style={{ marginRight: '8px', color: 'var(--primary)' }}></i> <strong>Phish Guard</strong></span>
          <span className="footer-sep">—</span>
          <span>ML-Powered Phishing & Smishing Detection Platform</span>
        </div>
        <div className="footer-sub">
          <i className="fas fa-map-marker-alt" style={{ marginRight: '5px' }}></i> Built for cybersecurity awareness in Kenya | Phish Guard v3.0
        </div>
      </div>
    </footer>
  );
}

export default Footer;
