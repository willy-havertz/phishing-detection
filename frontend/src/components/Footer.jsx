function Footer() {
  return (
    <footer className="footer">
      <div className="footer-content">
        <div className="footer-main">
          <span className="footer-brand"><img src="/logo.svg" alt="Phish Guard Logo" style={{ height: '20px', width: '20px', marginRight: '8px', verticalAlign: 'middle' }} /> <strong>Phish Guard</strong></span>
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
