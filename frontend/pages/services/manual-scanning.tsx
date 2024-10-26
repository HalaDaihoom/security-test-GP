import React, { CSSProperties } from 'react';
import Link from 'next/link';

const ManualScanning = () => {
  return (
    <div style={containerStyle}>
      <header style={headerStyle}>
        <div style={headerContentStyle}>
          <h1 style={logoStyle}>Vulnerability Scanner</h1>
          <nav style={navStyle}>
            <Link href="/home" style={navButtonStyle}>Home</Link>
            <Link href="/services/automatic-scanner" style={navButtonStyle}>Automatic Scanning</Link>
            <Link href="/services/manual-scanning" style={navButtonStyle}>Manual Scanning</Link>
            <Link href="/company/about" style={navButtonStyle}>About Us</Link>
            <Link href="/company/reviews" style={navButtonStyle}>Reviews</Link>
            <Link href="/company/contact" style={navButtonStyle}>Contact Us</Link>
          </nav>
        </div>
      </header>
      <main style={mainStyle}>
        <h2 style={headlineStyle}>Manual Scanning</h2>
        <p style={paragraphStyle}>
          Manual scanning is a critical process in identifying specific vulnerabilities in web applications. Here are three key vulnerabilities:
        </p>

        <h3 style={subHeadlineStyle}>1. Cross-Site Scripting (XSS)</h3>
        <p style={paragraphStyle}>
          XSS occurs when an attacker injects malicious scripts into content that is then served to users. This can lead to session hijacking, defacement, or redirection to malicious sites.
        </p>

        <h3 style={subHeadlineStyle}>2. SQL Injection (SQLi)</h3>
        <p style={paragraphStyle}>
          SQLi allows attackers to interfere with the queries that an application makes to its database. This can allow unauthorized access to sensitive data or even the entire database.
        </p>

        <h3 style={subHeadlineStyle}>3. Cross-Site Request Forgery (CSRF)</h3>
        <p style={paragraphStyle}>
          CSRF tricks the victim into submitting a request that they did not intend to make. It can exploit the trust that a web application has in the user's browser.
        </p>
      </main>
    </div>
  );
};

// Styles (same as in AutomaticScanner)
const containerStyle: CSSProperties = {
  margin: '0',
  padding: '0',
  boxSizing: 'border-box',
  fontFamily: 'Arial, sans-serif',
  backgroundColor: '#0A0A23',
  color: '#FFF',
};

const headerStyle: CSSProperties = {
  backgroundColor: '#1A1A3D',
  padding: '20px 40px',
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
};

const headerContentStyle: CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  width: '100%',
};

const logoStyle: CSSProperties = {
  color: '#FFF',
  fontSize: '26px',
  margin: '0',
};

const navStyle: CSSProperties = {
  display: 'flex',
  gap: '20px',
};

const navButtonStyle: CSSProperties = {
  color: '#FFF',
  textDecoration: 'none',
};

const mainStyle: CSSProperties = {
  padding: '40px',
};

const headlineStyle: CSSProperties = {
  fontSize: '36px',
  marginBottom: '20px',
};

const subHeadlineStyle: CSSProperties = {
  fontSize: '28px',
  marginTop: '20px',
};

const paragraphStyle: CSSProperties = {
  fontSize: '18px',
  marginBottom: '20px',
};

export default ManualScanning;
