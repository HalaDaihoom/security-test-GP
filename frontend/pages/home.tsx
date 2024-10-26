import React, { useEffect, useState, CSSProperties } from 'react';
import axios from 'axios';
import { useRouter } from 'next/router';
import Link from 'next/link';
import Cookies from 'js-cookie';

const Home = () => {
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    const token = Cookies.get('token');

    if (!token) {
      router.push('/login');
    } else {
      axios
        .get('http://localhost:5000/api/Home/protected', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        })
        .then((response) => {
          setMessage(response.data.message);
        })
        .catch((err) => {
          console.error('Error fetching protected resource:', err);
          setError('Error fetching protected resource');

          if (err.response && err.response.status === 401) {
            router.push('/login');
          }
        });
    }
  }, [router]);

  const handleLogout = () => {
    Cookies.remove('token');
    router.push('/login');
  };

  // Client-side useEffect for dropdown hover functionality
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const dropdowns = document.querySelectorAll('.dropdown');
      dropdowns.forEach((element) => {
        element.addEventListener('mouseover', () => {
          (element.querySelector('.dropdown-content') as HTMLElement).style.display = 'block';
        });
        element.addEventListener('mouseout', () => {
          (element.querySelector('.dropdown-content') as HTMLElement).style.display = 'none';
        });
      });
    }
  }, []);

  return (
    <div style={containerStyle}>
      <header style={headerStyle}>
        <div style={headerContentStyle}>
          <h1 style={logoStyle}>Vulnerability Scanner</h1>
          <nav style={navStyle}>
            {/* Scanners Dropdown */}
            <div className="dropdown" style={dropdownStyle}>
              <button style={navButtonStyle}>Scanners</button>
              <div className="dropdown-content" style={dropdownContentStyle}>
                <Link href="/scanners/automatic-scanner" style={dropdownItemStyle}>
                  <img src="/auto.png" alt="Automatic Scanner" style={iconStyle} />
                  Automatic Scanner
                </Link>
                <Link href="/scanners/xss-scanner" style={dropdownItemStyle}>
                  <img src="/xss.png" alt="XSS Scanner" style={iconStyle} />
                  "XSS Scanner
                </Link>
                <Link href="/scanners/sqli-finder" style={dropdownItemStyle}>
                  <img src="/sqlo.png" alt="SQLI Scanner" style={iconStyle} />
                  SQLI Scanner
                </Link>
                <Link href="/scanners/csrf-scanner" style={dropdownItemStyle}>
                  <img src="/csrf.png" alt="CSRF Scanner" style={iconStyle} />
                  CSRF Scanner
                </Link>
              </div>
            </div>

          {/* Services */}
<div className="dropdown" style={dropdownStyle}>
  <button style={navButtonStyle}>Services</button>
  <div className="dropdown-content" style={dropdownContentStyle}>
    <Link href="/services/automatic-scanner" style={dropdownItemStyle}>
      Automatic Scanning
    </Link>
    <Link href="/services/manual-scanner" style={dropdownItemStyle}>
      Manual Scanning
    </Link>
  </div>
</div>

{/* Company */}
<div className="dropdown" style={dropdownStyle}>
  <button style={navButtonStyle}>Company</button>
  <div className="dropdown-content" style={dropdownContentStyle}>
    <Link href="/company/about" style={dropdownItemStyle}>
      About Us
    </Link>
    <Link href="/company/reviews" style={dropdownItemStyle}>
      Reviews
    </Link>
    <Link href="/company/contact" style={dropdownItemStyle}>
      Contact Us
    </Link>
  </div>
</div>

{/* Profile */}
<div className="dropdown" style={dropdownStyle}>
  <button style={navButtonStyle}>Profile</button>
  <div className="dropdown-content" style={dropdownContentStyle}>
    <Link href="/profile/settings" style={dropdownItemStyle}>
      Account Settings
    </Link>
    <Link href="/profile/subscription" style={dropdownItemStyle}>
      Subscription
    </Link>
  </div>
</div>


            {/* Logout */}
            <button style={logoutButtonStyle} onClick={handleLogout}>
              Logout
            </button>
          </nav>
        </div>
      </header>

      <main style={mainStyle}>
        <div style={textSectionStyle}>
          <h2 style={headlineStyle}>
            Get a hacker's perspective on your web apps, network, and cloud
          </h2>
          <p style={paragraphStyle}>
            Pentest-Tools.com helps security teams run the key steps of a
            penetration test, easily and without expert hacking skills.
          </p>
          <ul style={bulletListStyle}>
            <li>Automatically map the attack surface</li>
            <li>Scan for the latest critical vulnerabilities</li>
            <li>Exploit to assess the business risk</li>
          </ul>
        </div>
        <div style={imageSectionStyle}></div>
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
  backgroundColor: '#0A0A23', // Dark Navy
};

const headerStyle: CSSProperties = {
  backgroundColor: '#1A1A3D', // Slightly lighter navy
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

const dropdownStyle: CSSProperties = {
  position: 'relative',
  display: 'inline-block',
};

const dropdownContentStyle: CSSProperties = {
  display: 'none',
  position: 'absolute',
  backgroundColor: '#FFF',
  minWidth: '200px',
  boxShadow: '0px 8px 16px 0px rgba(0,0,0,0.2)',
  zIndex: 1,
  borderRadius: '8px',
  padding: '10px 0',
};

const dropdownItemStyle: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  padding: '10px 20px',
  textDecoration: 'none',
  color: '#333',
  fontSize: '16px',
};

const iconStyle: CSSProperties = {
  width: '24px',
  height: '24px',
  marginRight: '10px',
};

const navButtonStyle: CSSProperties = {
  background: 'none',
  border: 'none',
  color: '#FFF',
  fontSize: '16px',
  cursor: 'pointer',
  padding: '14px 16px',
};

const logoutButtonStyle: CSSProperties = {
  backgroundColor: '#1A1A1A',
  border: '1px solid #FFF',
  padding: '10px 20px',
  color: '#FFF',
  fontSize: '16px',
  cursor: 'pointer',
  borderRadius: '4px',
  marginLeft: '10px',
};

const mainStyle: CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  padding: '80px 40px',
  color: '#FFF',
};

const textSectionStyle: CSSProperties = {
  flex: 1,
  marginRight: '40px',
};

const headlineStyle: CSSProperties = {
  fontSize: '48px',
  fontWeight: 'bold',
  marginBottom: '20px',
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

const imageSectionStyle: CSSProperties = {
  flex: 1,
  backgroundImage: "url('/lock-symbol-and-protection-image_15692197.jpg')",
  backgroundSize: 'cover',
  backgroundPosition: 'center',
  borderRadius: '12px',
};

export default Home;
