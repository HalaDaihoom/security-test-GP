import React, { CSSProperties } from 'react';
import Link from 'next/link';

const Reviews = () => {
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
        <h2 style={headlineStyle}>User Reviews</h2>
        <ul style={reviewListStyle}>
          <li style={reviewItemStyle}>
            <strong>John Doe:</strong> "The automatic scanning tool helped us identify vulnerabilities in our app quickly and efficiently!"
          </li>
          <li style={reviewItemStyle}>
            <strong>Jane Smith:</strong> "The manual scanning techniques provided detailed insights that improved our security posture."
          </li>
          <li style={reviewItemStyle}>
            <strong>Tom Brown:</strong> "Great service! The vulnerability reports were thorough and easy to understand."
          </li>
        </ul>
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

const reviewListStyle: CSSProperties = {
  listStyle: 'none',
  padding: '0',
};

const reviewItemStyle: CSSProperties = {
  fontSize: '18px',
  marginBottom: '10px',
};

export default Reviews;
