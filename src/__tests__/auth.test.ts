import jwt from 'jsonwebtoken';
import { AuthService, TokenPayload, TokenPair } from '../AuthService';
import { authMiddleware } from '../middleware';
import { decodeToken, isTokenExpired, getTokenTTL } from '../index';
import { Request, Response, NextFunction } from 'express';

// ─── Test Constants ──────────────────────────────────────────────────────────

const ACCESS_SECRET = 'test-access-secret-key';
const REFRESH_SECRET = 'test-refresh-secret-key';

const testUser: TokenPayload = {
  userId: 'user-123',
  email: 'test@example.com',
  roles: ['user'],
};

const adminUser: TokenPayload = {
  userId: 'admin-456',
  email: 'admin@example.com',
  roles: ['admin', 'user'],
};

function createService(overrides?: Partial<Parameters<typeof AuthService['prototype']['generateTokens']>>) {
  return new AuthService({
    accessTokenSecret: ACCESS_SECRET,
    refreshTokenSecret: REFRESH_SECRET,
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
  });
}

// ─── AuthService ─────────────────────────────────────────────────────────────

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(() => {
    service = createService();
  });

  // ── Token Generation ────────────────────────────────────────────────────

  describe('generateTokens', () => {
    it('should return an access token, refresh token, and expiresIn', () => {
      const tokens = service.generateTokens(testUser);

      expect(tokens).toHaveProperty('accessToken');
      expect(tokens).toHaveProperty('refreshToken');
      expect(tokens).toHaveProperty('expiresIn');
      expect(typeof tokens.accessToken).toBe('string');
      expect(typeof tokens.refreshToken).toBe('string');
      expect(typeof tokens.expiresIn).toBe('number');
    });

    it('should produce valid JWT strings with three dot-separated parts', () => {
      const tokens = service.generateTokens(testUser);

      expect(tokens.accessToken.split('.')).toHaveLength(3);
      expect(tokens.refreshToken.split('.')).toHaveLength(3);
    });

    it('should embed the correct payload in the access token', () => {
      const tokens = service.generateTokens(testUser);
      const decoded = jwt.verify(tokens.accessToken, ACCESS_SECRET) as jwt.JwtPayload;

      expect(decoded.userId).toBe(testUser.userId);
      expect(decoded.email).toBe(testUser.email);
      expect(decoded.roles).toEqual(testUser.roles);
    });

    it('should set the refresh token with type "refresh"', () => {
      const tokens = service.generateTokens(testUser);
      const decoded = jwt.verify(tokens.refreshToken, REFRESH_SECRET) as jwt.JwtPayload;

      expect(decoded.userId).toBe(testUser.userId);
      expect(decoded.type).toBe('refresh');
    });

    it('should calculate expiresIn correctly for default 15m expiry', () => {
      const tokens = service.generateTokens(testUser);
      expect(tokens.expiresIn).toBe(900); // 15 * 60
    });

    it('should respect custom expiry options', () => {
      const customService = new AuthService({
        accessTokenSecret: ACCESS_SECRET,
        refreshTokenSecret: REFRESH_SECRET,
        accessTokenExpiry: '1h',
        refreshTokenExpiry: '30d',
      });

      const tokens = customService.generateTokens(testUser);
      expect(tokens.expiresIn).toBe(3600);
    });

    it('should include issuer and audience when configured', () => {
      const customService = new AuthService({
        accessTokenSecret: ACCESS_SECRET,
        refreshTokenSecret: REFRESH_SECRET,
        issuer: 'my-app',
        audience: 'my-api',
      });

      const tokens = customService.generateTokens(testUser);
      const decoded = jwt.verify(tokens.accessToken, ACCESS_SECRET) as jwt.JwtPayload;

      expect(decoded.iss).toBe('my-app');
      expect(decoded.aud).toBe('my-api');
    });

    it('should generate unique tokens on each call', () => {
      const tokens1 = service.generateTokens(testUser);
      const tokens2 = service.generateTokens(testUser);

      expect(tokens1.accessToken).not.toBe(tokens2.accessToken);
      expect(tokens1.refreshToken).not.toBe(tokens2.refreshToken);
    });
  });

  // ── Token Verification ──────────────────────────────────────────────────

  describe('verifyAccessToken', () => {
    it('should return the payload for a valid access token', () => {
      const tokens = service.generateTokens(testUser);
      const payload = service.verifyAccessToken(tokens.accessToken);

      expect(payload).toEqual({
        userId: testUser.userId,
        email: testUser.email,
        roles: testUser.roles,
      });
    });

    it('should throw for an expired token', () => {
      const expired = jwt.sign(testUser, ACCESS_SECRET, { expiresIn: '0s' });

      expect(() => service.verifyAccessToken(expired)).toThrow();
    });

    it('should throw for a token signed with the wrong secret', () => {
      const bad = jwt.sign(testUser, 'wrong-secret', { expiresIn: '15m' });

      expect(() => service.verifyAccessToken(bad)).toThrow();
    });

    it('should throw for a completely invalid token string', () => {
      expect(() => service.verifyAccessToken('not.a.token')).toThrow();
    });

    it('should throw for an empty string', () => {
      expect(() => service.verifyAccessToken('')).toThrow();
    });

    it('should throw for a tampered token', () => {
      const tokens = service.generateTokens(testUser);
      const tampered = tokens.accessToken.slice(0, -5) + 'XXXXX';

      expect(() => service.verifyAccessToken(tampered)).toThrow();
    });
  });

  // ── Token Refresh ───────────────────────────────────────────────────────

  describe('refreshTokens', () => {
    it('should return a new token pair given a valid refresh token', () => {
      const original = service.generateTokens(testUser);
      const refreshed = service.refreshTokens(original.refreshToken);

      expect(refreshed).toHaveProperty('accessToken');
      expect(refreshed).toHaveProperty('refreshToken');
      expect(refreshed).toHaveProperty('expiresIn');
    });

    it('should return different tokens from the original pair', () => {
      const original = service.generateTokens(testUser);
      const refreshed = service.refreshTokens(original.refreshToken);

      expect(refreshed.accessToken).not.toBe(original.accessToken);
      expect(refreshed.refreshToken).not.toBe(original.refreshToken);
    });

    it('should revoke the old refresh token after rotation', () => {
      const original = service.generateTokens(testUser);
      service.refreshTokens(original.refreshToken);

      // Using the same refresh token again should fail because it was revoked
      expect(() => service.refreshTokens(original.refreshToken)).toThrow('Refresh token has been revoked');
    });

    it('should throw when given an access token instead of a refresh token', () => {
      const tokens = service.generateTokens(testUser);

      // Access token does not have type: 'refresh' and is signed with a different secret
      expect(() => service.refreshTokens(tokens.accessToken)).toThrow();
    });

    it('should throw for an expired refresh token', () => {
      const expired = jwt.sign(
        { userId: 'user-123', type: 'refresh' },
        REFRESH_SECRET,
        { expiresIn: '0s' }
      );

      expect(() => service.refreshTokens(expired)).toThrow();
    });

    it('should throw for a token without type "refresh"', () => {
      const noType = jwt.sign(
        { userId: 'user-123', type: 'access' },
        REFRESH_SECRET,
        { expiresIn: '7d' }
      );

      expect(() => service.refreshTokens(noType)).toThrow('Invalid token type');
    });
  });

  // ── Token Revocation ────────────────────────────────────────────────────

  describe('revokeToken / isTokenRevoked', () => {
    it('should mark a token as revoked', () => {
      const tokens = service.generateTokens(testUser);

      expect(service.isTokenRevoked(tokens.accessToken)).toBe(false);
      service.revokeToken(tokens.accessToken);
      expect(service.isTokenRevoked(tokens.accessToken)).toBe(true);
    });

    it('should reject verification of a revoked access token', () => {
      const tokens = service.generateTokens(testUser);
      service.revokeToken(tokens.accessToken);

      expect(() => service.verifyAccessToken(tokens.accessToken)).toThrow('Token has been revoked');
    });
  });

  // ── Constructor defaults ────────────────────────────────────────────────

  describe('constructor defaults', () => {
    it('should default accessTokenExpiry to 15m and refreshTokenExpiry to 7d', () => {
      const minimal = new AuthService({
        accessTokenSecret: ACCESS_SECRET,
        refreshTokenSecret: REFRESH_SECRET,
      });

      const tokens = minimal.generateTokens(testUser);
      expect(tokens.expiresIn).toBe(900); // 15m = 900s
    });
  });
});

// ─── Utility Functions (index.ts) ────────────────────────────────────────────

describe('Utility functions', () => {
  const service = new AuthService({
    accessTokenSecret: ACCESS_SECRET,
    refreshTokenSecret: REFRESH_SECRET,
    accessTokenExpiry: '1h',
  });

  describe('decodeToken', () => {
    it('should decode a valid JWT without verifying the signature', () => {
      const tokens = service.generateTokens(testUser);
      const decoded = decodeToken(tokens.accessToken);

      expect(decoded).not.toBeNull();
      expect(decoded!.userId).toBe(testUser.userId);
      expect(decoded!.email).toBe(testUser.email);
    });

    it('should return null for a non-JWT string', () => {
      expect(decodeToken('hello')).toBeNull();
    });

    it('should return null for an empty string', () => {
      expect(decodeToken('')).toBeNull();
    });

    it('should return null for a string with three parts but invalid base64', () => {
      // Three dots but payload is not valid base64 JSON
      expect(decodeToken('a.!!!.c')).toBeNull();
    });
  });

  describe('isTokenExpired', () => {
    it('should return false for a fresh token', () => {
      const tokens = service.generateTokens(testUser);
      expect(isTokenExpired(tokens.accessToken)).toBe(false);
    });

    it('should return true for an expired token', () => {
      const expired = jwt.sign(testUser, ACCESS_SECRET, { expiresIn: '0s' });
      expect(isTokenExpired(expired)).toBe(true);
    });

    it('should return true for an invalid token', () => {
      expect(isTokenExpired('garbage')).toBe(true);
    });

    it('should return true for a token without exp claim', () => {
      const noExp = jwt.sign(testUser, ACCESS_SECRET);
      // jwt.sign without expiresIn does not include exp by default
      expect(isTokenExpired(noExp)).toBe(true);
    });
  });

  describe('getTokenTTL', () => {
    it('should return a positive number for a fresh token', () => {
      const tokens = service.generateTokens(testUser);
      const ttl = getTokenTTL(tokens.accessToken);

      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(3600);
    });

    it('should return 0 for an expired token', () => {
      const expired = jwt.sign(testUser, ACCESS_SECRET, { expiresIn: '0s' });
      expect(getTokenTTL(expired)).toBe(0);
    });

    it('should return 0 for an invalid token', () => {
      expect(getTokenTTL('not-a-token')).toBe(0);
    });
  });
});

// ─── authMiddleware ──────────────────────────────────────────────────────────

describe('authMiddleware', () => {
  let service: AuthService;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let statusMock: jest.Mock;
  let jsonMock: jest.Mock;

  beforeEach(() => {
    service = new AuthService({
      accessTokenSecret: ACCESS_SECRET,
      refreshTokenSecret: REFRESH_SECRET,
    });

    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });

    mockReq = { headers: {} };
    mockRes = { status: statusMock } as Partial<Response>;
    mockNext = jest.fn();
  });

  function runMiddleware(
    roles: string[] = [],
    options: { optional?: boolean } = {}
  ) {
    const mw = authMiddleware(service, roles, options);
    return mw(mockReq as Request, mockRes as Response, mockNext);
  }

  it('should call next and attach user for a valid token', () => {
    const tokens = service.generateTokens(testUser);
    mockReq.headers = { authorization: `Bearer ${tokens.accessToken}` };

    runMiddleware();

    expect(mockNext).toHaveBeenCalled();
    expect((mockReq as any).user).toEqual({
      userId: testUser.userId,
      email: testUser.email,
      roles: testUser.roles,
    });
  });

  it('should return 401 when no Authorization header is present', () => {
    runMiddleware();

    expect(statusMock).toHaveBeenCalledWith(401);
    expect(jsonMock).toHaveBeenCalledWith({ error: 'No token provided' });
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should return 401 when Authorization header does not start with Bearer', () => {
    mockReq.headers = { authorization: 'Basic abc123' };

    runMiddleware();

    expect(statusMock).toHaveBeenCalledWith(401);
    expect(jsonMock).toHaveBeenCalledWith({ error: 'No token provided' });
  });

  it('should return 401 for an invalid token', () => {
    mockReq.headers = { authorization: 'Bearer invalid.token.here' };

    runMiddleware();

    expect(statusMock).toHaveBeenCalledWith(401);
  });

  it('should return 401 with "Token expired" for an expired token', () => {
    const expired = jwt.sign(testUser, ACCESS_SECRET, { expiresIn: '0s' });
    mockReq.headers = { authorization: `Bearer ${expired}` };

    runMiddleware();

    expect(statusMock).toHaveBeenCalledWith(401);
    expect(jsonMock).toHaveBeenCalledWith({ error: 'Token expired' });
  });

  it('should return 403 when the user lacks the required role', () => {
    const tokens = service.generateTokens(testUser); // roles: ['user']
    mockReq.headers = { authorization: `Bearer ${tokens.accessToken}` };

    runMiddleware(['admin']);

    expect(statusMock).toHaveBeenCalledWith(403);
    expect(jsonMock).toHaveBeenCalledWith({ error: 'Insufficient permissions' });
  });

  it('should pass when the user has one of the required roles', () => {
    const tokens = service.generateTokens(adminUser); // roles: ['admin', 'user']
    mockReq.headers = { authorization: `Bearer ${tokens.accessToken}` };

    runMiddleware(['admin']);

    expect(mockNext).toHaveBeenCalled();
  });

  // ── Optional mode ───────────────────────────────────────────────────────

  describe('optional mode', () => {
    it('should call next without error when no token is provided', () => {
      runMiddleware([], { optional: true });

      expect(mockNext).toHaveBeenCalled();
      expect(statusMock).not.toHaveBeenCalled();
    });

    it('should call next without error for an invalid token', () => {
      mockReq.headers = { authorization: 'Bearer bad.token.value' };

      runMiddleware([], { optional: true });

      expect(mockNext).toHaveBeenCalled();
      expect(statusMock).not.toHaveBeenCalled();
    });

    it('should still attach user when a valid token is provided', () => {
      const tokens = service.generateTokens(testUser);
      mockReq.headers = { authorization: `Bearer ${tokens.accessToken}` };

      runMiddleware([], { optional: true });

      expect(mockNext).toHaveBeenCalled();
      expect((mockReq as any).user).toEqual({
        userId: testUser.userId,
        email: testUser.email,
        roles: testUser.roles,
      });
    });
  });
});
