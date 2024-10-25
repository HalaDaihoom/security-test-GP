import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/router';

const Home = () => {
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('token');

    if (!token) {
      // Redirect to the login page if no token is found
      router.push('/login');
    } else {
      // Fetch the protected resource with the token in the Authorization header
      axios
        .get('http://localhost:5000/api/Home/protected', {
          headers: {
            Authorization: `Bearer ${token}`, // Attaching the token to the request
          },
        })
        .then((response) => {
          // Successfully fetched the protected resource
          setMessage(response.data.message); // Set the message received from the API
        })
        .catch((err) => {
          // Handle error when fetching the protected resource
          console.error('Error fetching protected resource:', err);
          setError('Error fetching protected resource');
          
          // If the error is a 401 Unauthorized, redirect to the login page
          if (err.response && err.response.status === 401) {
            router.push('/login');
          }
        });
    }
  }, [router]);

  return (
    <div>
      <h1>Welcome to the Protected Home Page</h1>
      {/* Display message or error based on the state */}
      {message && <p>{message}</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
};

export default Home;
