import { useState } from 'react';
import { useRouter } from 'next/router';

const Login: React.FC = () => {
  const [email, setEmail] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string>('');
  const router = useRouter();

  const handleLogin = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    try {
      const response = await fetch('http://localhost:5240/Home', { // Update with your backend API URL
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      if (response.ok) {
        // Redirect to the dashboard or handle success
        router.push('/dashboard');
      } else {
        const data = await response.json();
        setErrorMessage(data.message || 'Login failed. Please try again.');
      }
    } catch (error) {
      console.error('Error logging in:', error);
      setErrorMessage('An error occurred. Please try again later.');
    }
  };

  return (
    <div>
      <style jsx global>{`
        body {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
      `}</style>
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          backgroundImage: "url('/lock-symbol-and-protection-image_15692197.jpg')", // Your background image path here
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
        }}
      >
        <div
          style={{
            padding: '25px',
            borderRadius: '20px',
            backgroundColor: 'rgba(255, 255, 255, 0.15)',
            boxShadow: '0 6px 20px rgba(0, 0, 0, 0.6)',
            backdropFilter: 'blur(15px)',
            WebkitBackdropFilter: 'blur(15px)',
            border: '2px solid rgba(255, 255, 255, 0.3)',
            width: '400px',
            maxWidth: '85%',
            transition: 'transform 0.2s',
          }}
        >
          <h1 style={{ textAlign: 'center', color: '#fff', fontWeight: 'bold', fontSize: '24px', letterSpacing: '1px' }}>
            Welcome!
          </h1>
          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <input
              type="email"
              placeholder="Enter your email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              style={{
                padding: '10px',
                border: '1px solid rgba(255, 255, 255, 0.4)',
                borderRadius: '8px',
                background: 'rgba(255, 255, 255, 0.9)',
                color: '#333',
                transition: 'border-color 0.2s',
              }}
              onFocus={(e) => (e.target.style.borderColor = '#6a5acd')}
              onBlur={(e) => (e.target.style.borderColor = 'rgba(255, 255, 255, 0.4)')}
            />
            <input
              type="password"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{
                padding: '10px',
                border: '1px solid rgba(255, 255, 255, 0.4)',
                borderRadius: '8px',
                background: 'rgba(255, 255, 255, 0.9)',
                color: '#333',
                transition: 'border-color 0.2s',
              }}
              onFocus={(e) => (e.target.style.borderColor = '#6a5acd')}
              onBlur={(e) => (e.target.style.borderColor = 'rgba(255, 255, 255, 0.4)')}
            />
            <button
              type="submit"
              style={{
                padding: '12px',
                backgroundColor: '#2f1e6f',
                color: '#fff',
                border: 'none',
                borderRadius: '8px',
                cursor: 'pointer',
                fontSize: '16px',
                fontWeight: '600',
                transition: 'background-color 0.3s',
              }}
              onMouseOver={(e) => (e.currentTarget.style.backgroundColor = '#1d1447')}
              onMouseOut={(e) => (e.currentTarget.style.backgroundColor = '#2f1e6f')}
            >
              Sign In
            </button>

            {errorMessage && (
              <p style={{ color: '#ff4d4d', textAlign: 'center', fontWeight: '500' }}>{errorMessage}</p>
            )}
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;
