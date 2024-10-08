import React from 'react';

const Dashboard: React.FC = () => {
  return (
    <div>
      <style jsx global>{`
        body {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background-color: #000c19; /* Matching dark background color */
        }
      `}</style>
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          backgroundImage: "url('/lock-symbol-and-protection-image_15692197.jpg')", // Ensure the image path is correct
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
        }}
      >
        <div
          style={{
            padding: '25px',
            borderRadius: '20px',
            backgroundColor: 'rgba(255, 255, 255, 0.15)', // Transparent background for glass effect
            boxShadow: '0 6px 20px rgba(0, 0, 0, 0.6)', // Deeper shadow
            backdropFilter: 'blur(15px)', // Blur effect for glassy appearance
            WebkitBackdropFilter: 'blur(15px)', // Safari support
            border: '2px solid rgba(255, 255, 255, 0.3)', // Border for effect
            width: '80%',
            maxWidth: '1200px',
            textAlign: 'center',
            color: '#fff', // Ensuring text color is white
          }}
        >
          <h1 style={{ fontSize: '36px', fontWeight: 'bold', marginBottom: '20px', color: '#fff' }}>
            Welcome to Your Dashboard!
          </h1>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-around',
              gap: '20px',
              flexWrap: 'wrap',
            }}
          >
            <div
              style={{
                backgroundColor: 'rgba(255, 255, 255, 0.1)', // Semi-transparent background for cards
                padding: '20px',
                borderRadius: '10px',
                width: '250px',
                boxShadow: '0 4px 15px rgba(0, 0, 0, 0.3)',
                border: '1px solid rgba(255, 255, 255, 0.3)',
              }}
            >
              <h2 style={{ color: '#f0f0f0', fontWeight: 'bold', fontSize: '20px' }}>Profile</h2>
              <p style={{ color: '#ddd', fontSize: '14px' }}>Update your profile information</p>
            </div>
            <div
              style={{
                backgroundColor: 'rgba(255, 255, 255, 0.1)', // Semi-transparent background for cards
                padding: '20px',
                borderRadius: '10px',
                width: '250px',
                boxShadow: '0 4px 15px rgba(0, 0, 0, 0.3)',
                border: '1px solid rgba(255, 255, 255, 0.3)',
              }}
            >
              <h2 style={{ color: '#f0f0f0', fontWeight: 'bold', fontSize: '20px' }}>Settings</h2>
              <p style={{ color: '#ddd', fontSize: '14px' }}>Manage account settings</p>
            </div>
            <div
              style={{
                backgroundColor: 'rgba(255, 255, 255, 0.1)', // Semi-transparent background for cards
                padding: '20px',
                borderRadius: '10px',
                width: '250px',
                boxShadow: '0 4px 15px rgba(0, 0, 0, 0.3)',
                border: '1px solid rgba(255, 255, 255, 0.3)',
              }}
            >
              <h2 style={{ color: '#f0f0f0', fontWeight: 'bold', fontSize: '20px' }}>Notifications</h2>
              <p style={{ color: '#ddd', fontSize: '14px' }}>Check your latest updates</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
