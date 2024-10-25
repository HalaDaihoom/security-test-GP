import React, { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/router';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  const handleLogin = () => {
    // Send login request to the backend
    axios
      .post('http://localhost:5000/api/Home/login', {
        email,
        password,
      })
      .then((response) => {
        const token = response.data.token; // Assuming the response has a 'token' field
        localStorage.setItem('token', token); // Store the JWT token in localStorage
        router.push('/home'); // Redirect to the protected home page
      })
      .catch((err) => {
        console.error('Login failed:', err);
        setError('Invalid email or password');
      });
  };

  return (
    <div>
      <h1>Login Page</h1>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button onClick={handleLogin}>Login</button>
    </div>
  );
};

export default Login;
