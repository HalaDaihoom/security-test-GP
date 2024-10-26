import React, { CSSProperties, useState } from 'react';
import Link from 'next/link';

const ContactUs = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle form submission logic here
    alert(`Message sent!\nName: ${name}\nEmail: ${email}\nMessage: ${message}`);
  };

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
        <h2 style={headlineStyle}>Contact Us</h2>
        <form onSubmit={handleSubmit} style={formStyle}>
          <label style={labelStyle}>
            Name:
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              style={inputStyle}
              required
            />
          </label>
          <label style={labelStyle}>
            Email:
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={inputStyle}
              required
            />
          </label>
          <label style={labelStyle}>
            Message:
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              style={textareaStyle}
              required
            />
          </label>
          <button type="submit" style={submitButtonStyle}>Send</button>
        </form>
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

const formStyle: CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: '20px',
};

const labelStyle: CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  color: '#FFF',
};

const inputStyle: CSSProperties = {
  padding: '10px',
  borderRadius: '4px',
  border: '1px solid #333',
};

const textareaStyle: CSSProperties = {
  padding: '10px',
  borderRadius: '4px',
  border: '1px solid #333',
  minHeight: '100px',
};

const submitButtonStyle: CSSProperties = {
  backgroundColor: '#1A1A1A',
  border: '1px solid #FFF',
  padding: '10px 20px',
  color: '#FFF',
  fontSize: '16px',
  cursor: 'pointer',
  borderRadius: '4px',
};

export default ContactUs;
