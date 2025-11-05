// Admin authentication utilities
import { jwtVerify, SignJWT } from 'jose';

const ADMIN_SECRET = new TextEncoder().encode(
  process.env.ADMIN_JWT_SECRET || 'your-admin-secret-key-change-in-production'
);

// Hardcoded admin credentials (in production, use database)
const ADMIN_CREDENTIALS = {
  email: process.env.ADMIN_EMAIL || 'admin@kuberjitemple.org',
  password: process.env.ADMIN_PASSWORD || 'Admin@123',
  role: 'admin'
};

export async function verifyAdminCredentials(email, password) {
  return email === ADMIN_CREDENTIALS.email && password === ADMIN_CREDENTIALS.password;
}

export async function createAdminToken(email) {
  const token = await new SignJWT({ email, role: 'admin' })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('24h')
    .sign(ADMIN_SECRET);
  
  return token;
}

export async function verifyAdminToken(token) {
  try {
    const { payload } = await jwtVerify(token, ADMIN_SECRET);
    return payload.role === 'admin' ? payload : null;
  } catch (error) {
    return null;
  }
}

export function getAdminTokenFromRequest(request) {
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  // Also check cookies
  const cookies = request.headers.get('cookie');
  if (cookies) {
    const tokenCookie = cookies.split(';').find(c => c.trim().startsWith('admin_token='));
    if (tokenCookie) {
      return tokenCookie.split('=')[1];
    }
  }
  
  return null;
}
