export { AuthService } from './AuthService';
export type { TokenPayload, TokenPair, AuthServiceOptions } from './AuthService';
export { authMiddleware } from './middleware';

export interface JwtPayload {
  [key: string]: unknown;
  exp?: number;
  iat?: number;
  sub?: string;
}

// Utility: Extract user from token without verification
export function decodeToken(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], 'base64').toString('utf8');
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

// Check if token is expired
export function isTokenExpired(token: string): boolean {
  const payload = decodeToken(token);
  if (!payload || !payload.exp) return true;
  return Date.now() >= payload.exp * 1000;
}

// Get time until token expires in seconds
export function getTokenTTL(token: string): number {
  const payload = decodeToken(token);
  if (!payload || !payload.exp) return 0;
  const remaining = payload.exp * 1000 - Date.now();
  return Math.max(0, Math.floor(remaining / 1000));
}

// Extract the subject claim from a token without verification
export function getTokenSubject(token: string): string | null {
  const payload = decodeToken(token);
  return payload?.sub ?? null;
}
