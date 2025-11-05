// Admin authentication utilities
import crypto from 'crypto';

const ADMIN_SECRET = process.env.ADMIN_JWT_SECRET || 'your-admin-secret-key-change-in-production';

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
  const payload = {
    email,
    role: 'admin',
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
  };
  
  const token = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = crypto.createHmac('sha256', ADMIN_SECRET).update(token).digest('base64');
  
  return `${token}.${signature}`;
}

export async function verifyAdminToken(token) {
  try {
    if (!token || !token.includes('.')) return null;
    
    const [payloadBase64, signature] = token.split('.');
    const expectedSignature = crypto.createHmac('sha256', ADMIN_SECRET).update(payloadBase64).digest('base64');
    
    if (signature !== expectedSignature) return null;
    
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString());
    
    // Check expiration
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    
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
