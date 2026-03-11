# JWT Auth Service

![Node.js](https://img.shields.io/badge/Node.js-20-339933?style=flat-square&logo=node.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

Lightweight JWT authentication service with refresh tokens, role-based access control, and secure token rotation.

## Features

- **Access & Refresh Tokens** - Secure token pair strategy
- **Token Rotation** - Automatic refresh token rotation
- **Role-Based Access** - Built-in RBAC support
- **Blacklisting** - Token revocation support
- **TypeScript** - Full type safety
- **Express Middleware** - Easy integration

## Installation

```bash
npm install @marwantech/jwt-auth-service
```

## Quick Start

```typescript
import { AuthService, authMiddleware } from '@marwantech/jwt-auth-service';

// Initialize
const auth = new AuthService({
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
});

// Generate tokens
const tokens = auth.generateTokens({
  userId: 'user-123',
  email: 'user@example.com',
  roles: ['user', 'admin'],
});

// Protect routes
app.get('/api/protected', authMiddleware(auth), (req, res) => {
  res.json({ user: req.user });
});

// Role-based access
app.get('/api/admin', authMiddleware(auth, ['admin']), (req, res) => {
  res.json({ message: 'Admin only' });
});
```

## API

### AuthService

```typescript
const auth = new AuthService(options);

// Generate token pair
auth.generateTokens(payload: TokenPayload): TokenPair

// Verify access token
auth.verifyAccessToken(token: string): TokenPayload

// Refresh tokens
auth.refreshTokens(refreshToken: string): TokenPair

// Revoke token
auth.revokeToken(token: string): void

// Check if revoked
auth.isTokenRevoked(token: string): boolean
```

### Middleware

```typescript
import { authMiddleware } from '@marwantech/jwt-auth-service';

// Basic auth check
app.use(authMiddleware(auth));

// With required roles
app.use(authMiddleware(auth, ['admin', 'moderator']));

// Optional auth (doesn't fail if no token)
app.use(authMiddleware(auth, [], { optional: true }));
```

## Token Rotation

Refresh tokens are automatically rotated on each use:

```typescript
// Old refresh token is invalidated
// New token pair is issued
const newTokens = auth.refreshTokens(oldRefreshToken);
```

## Configuration

```typescript
interface AuthServiceOptions {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  accessTokenExpiry?: string;  // Default: '15m'
  refreshTokenExpiry?: string; // Default: '7d'
  issuer?: string;
  audience?: string;
}
```

## Security Best Practices

1. Store refresh tokens in httpOnly cookies
2. Use short-lived access tokens (15 min)
3. Implement token rotation
4. Use secure, random secrets (256+ bits)
5. Always use HTTPS in production

## License

MIT
