import { NextResponse } from 'next/server';
import { getAdminTokenFromRequest, verifyAdminToken } from '@/lib/admin-auth';

export async function GET(request) {
  try {
    const token = getAdminTokenFromRequest(request);

    if (!token) {
      return NextResponse.json(
        { authenticated: false },
        { status: 401 }
      );
    }

    const payload = await verifyAdminToken(token);

    if (!payload) {
      return NextResponse.json(
        { authenticated: false },
        { status: 401 }
      );
    }

    return NextResponse.json({
      authenticated: true,
      user: { email: payload.email, role: payload.role }
    });
  } catch (error) {
    console.error('Admin verification error:', error);
    return NextResponse.json(
      { authenticated: false },
      { status: 401 }
    );
  }
}
