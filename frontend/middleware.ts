import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Middleware function to protect certain routes
export function middleware(request: NextRequest) {
  console.log('Middleware invoked for:', request.nextUrl.pathname); // Check if middleware is being triggered
  const token = request.cookies.get('token'); // Use cookies for secure storage

  // Redirect to login if token is missing on protected routes
  if (request.nextUrl.pathname.startsWith('/home') && !token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Allow the request to proceed if authenticated or not a protected route
  return NextResponse.next();
}

// Define the routes where the middleware should be applied
export const config = {
  matcher: ['/home/:path*'], // Protect the home page and any subroutes like /home/settings
};
