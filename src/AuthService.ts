import jwt, { SignOptions, JwtPayload } from 'jsonwebtoken';

export interface TokenPayload {
  userId: string;
  email: string;
  roles: string[];
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthServiceOptions {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  accessTokenExpiry?: string;
  refreshTokenExpiry?: string;
  issuer?: string;
  audience?: string;
}

export class AuthService {
  private accessTokenSecret: string;
  private refreshTokenSecret: string;
  private accessTokenExpiry: string;
  private refreshTokenExpiry: string;
  private issuer?: string;
  private audience?: string;
  private revokedTokens: Set<string> = new Set();

  constructor(options: AuthServiceOptions) {
    this.accessTokenSecret = options.accessTokenSecret;
    this.refreshTokenSecret = options.refreshTokenSecret;
    this.accessTokenExpiry = options.accessTokenExpiry || '15m';
    this.refreshTokenExpiry = options.refreshTokenExpiry || '7d';
    this.issuer = options.issuer;
    this.audience = options.audience;
  }

  /**
   * Generate access and refresh token pair
   */
  generateTokens(payload: TokenPayload): TokenPair {
    const signOptions: SignOptions = {
      expiresIn: this.accessTokenExpiry,
      ...(this.issuer && { issuer: this.issuer }),
      ...(this.audience && { audience: this.audience }),
    };

    const accessToken = jwt.sign(payload, this.accessTokenSecret, signOptions);

    const refreshToken = jwt.sign(
      { userId: payload.userId, type: 'refresh' },
      this.refreshTokenSecret,
      { expiresIn: this.refreshTokenExpiry }
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: this.parseExpiry(this.accessTokenExpiry),
    };
  }

  /**
   * Verify access token and return payload
   */
  verifyAccessToken(token: string): TokenPayload {
    if (this.isTokenRevoked(token)) {
      throw new Error('Token has been revoked');
    }

    const payload = jwt.verify(token, this.accessTokenSecret) as JwtPayload & TokenPayload;
    return {
      userId: payload.userId,
      email: payload.email,
      roles: payload.roles,
    };
  }

  /**
   * Refresh tokens using refresh token
   * Implements token rotation for security
   */
  refreshTokens(refreshToken: string): TokenPair {
    if (this.isTokenRevoked(refreshToken)) {
      throw new Error('Refresh token has been revoked');
    }

    const payload = jwt.verify(refreshToken, this.refreshTokenSecret) as JwtPayload;

    if (payload.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    // Revoke old refresh token (rotation)
    this.revokeToken(refreshToken);

    // Generate new token pair
    // Note: In production, fetch user data from database
    return this.generateTokens({
      userId: payload.userId,
      email: '', // Fetch from DB
      roles: [], // Fetch from DB
    });
  }

  /**
   * Revoke a token (add to blacklist)
   */
  revokeToken(token: string): void {
    this.revokedTokens.add(token);
  }

  /**
   * Check if token is revoked
   */
  isTokenRevoked(token: string): boolean {
    return this.revokedTokens.has(token);
  }

  /**
   * Parse expiry string to seconds
   */
  private parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) return 900; // Default 15 minutes

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 3600;
      case 'd': return value * 86400;
      default: return 900;
    }
  }
}
