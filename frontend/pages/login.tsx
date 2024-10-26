import React, { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/router';
import Cookies from 'js-cookie'; // Import js-cookie for handling cookies

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault(); // Prevent the default form submission
    // Send login request to the backend
    axios
      .post('http://localhost:5000/api/Home/login', {
        email,
        password,
      })
      .then((response) => {
        const token = response.data.token; // Assuming the response has a 'token' field
        Cookies.set('token', token, { expires: 1 }); // Store the JWT token in cookies for 1 day
        router.push('/home'); // Redirect to the protected home page
      })
      .catch((err) => {
        console.error('Login failed:', err);
        setError('Invalid email or password');
      });
  };

  return (
    <div>
      <style jsx global>{`
        body {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
      `}</style>
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          backgroundImage: "url('/lock-symbol-and-protection-image_15692197.jpg')", // Add your background image here
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
        }}
      >
        <div
          style={{
            padding: '20px',
            borderRadius: '16px',
            backgroundColor: 'rgba(255, 255, 255, 0.1)', // Semi-transparent background
            boxShadow: '0 4px 30px rgba(0, 0, 0, 0.6)', // Softer shadow
            backdropFilter: 'blur(10px)', // Glassy blur effect
            WebkitBackdropFilter: 'blur(10px)', // For Safari support
            border: '1px solid rgba(255, 255, 255, 0.3)', // Border for the glassy effect
            width: '450px',
          }}
        >
          <h1 style={{ textAlign: 'center', color: 'black', fontWeight: 'bold', fontSize: '25px' }}>Login</h1>
          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column' }}>
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              style={{
                padding: '10px',
                margin: '10px 0',
                border: '1px solid #ccc',
                borderRadius: '4px',
                backdropFilter: 'blur(5px)', // Slight blur for input fields
              }}
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{
                padding: '10px',
                margin: '10px 0',
                border: '1px solid #ccc',
                borderRadius: '4px',
                backdropFilter: 'blur(5px)', // Slight blur for input fields
              }}
            />
            <button
              type="submit"
              style={{
                padding: '10px',
                backgroundColor: '#000c19',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              Login
            </button>
            {error && <p style={{ color: 'red', textAlign: 'center' }}>{error}</p>}
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;
