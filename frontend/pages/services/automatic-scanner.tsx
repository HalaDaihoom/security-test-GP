import React, { CSSProperties } from 'react';
import Link from 'next/link';

const AutomaticScanner = () => {
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
        <h2 style={headlineStyle}>Automatic Scanning Tool</h2>
        <p style={paragraphStyle}>
          Our automatic scanning tool performs a comprehensive analysis of the provided URL to identify vulnerabilities.
        </p>
        <h3 style={subHeadlineStyle}>Key Features:</h3>
        <ul style={bulletListStyle}>
          <li>Full website scan for vulnerabilities</li>
          <li>Detailed reports on vulnerabilities found</li>
          <li>Severity ratings for each vulnerability</li>
        </ul>
        <h3 style={subHeadlineStyle}>How It Works:</h3>
        <p style={paragraphStyle}>
          1. Enter the URL to be scanned.<br />
          2. The tool performs various tests for common vulnerabilities.<br />
          3. A report is generated detailing the vulnerabilities found and their severity.
        </p>
      </main>
    </div>
  );
};

// Styles
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

const bulletListStyle: CSSProperties = {
  fontSize: '18px',
  listStyle: 'none',
  padding: '0',
};

export default AutomaticScanner;
