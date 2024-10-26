import React, { CSSProperties } from 'react';
import Link from 'next/link';

const AboutUs = () => {
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
        <h2 style={headlineStyle}>About Us</h2>
        <p style={paragraphStyle}>
          Our website provides cutting-edge tools for security teams to perform penetration testing and vulnerability assessments. We aim to empower teams with the resources they need to ensure the safety of their applications and infrastructure.
        </p>
        <p style={paragraphStyle}>
          We focus on making security accessible, providing automated tools and detailed guides on manual scanning techniques to help users understand the landscape of vulnerabilities.
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

const paragraphStyle: CSSProperties = {
  fontSize: '18px',
  marginBottom: '20px',
};

export default AboutUs;
