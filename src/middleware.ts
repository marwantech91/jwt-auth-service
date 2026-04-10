import { Request, Response, NextFunction } from 'express';
import { AuthService, TokenPayload } from './AuthService';

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

interface MiddlewareOptions {
  optional?: boolean;
}

/**
 * Express middleware for JWT authentication
 */
export function authMiddleware(
  auth: AuthService,
  requiredRoles: string[] = [],
  options: MiddlewareOptions = {}
) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      if (options.optional) {
        return next();
      }
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);

    try {
      const payload = auth.verifyAccessToken(token);

      // Check required roles
      if (requiredRoles.length > 0) {
        const hasRole = requiredRoles.some((role) => payload.roles.includes(role));
        if (!hasRole) {
          return res.status(403).json({ error: 'Insufficient permissions' });
        }
      }

      req.user = payload;
      next();
    } catch (error) {
      if (options.optional) {
        return next();
      }

      if (error instanceof Error) {
        if (error.name === 'TokenExpiredError') {
          return res.status(401).json({ error: 'Token expired' });
        }
        if (error.name === 'JsonWebTokenError') {
          return res.status(401).json({ error: 'Invalid token' });
        }
      }

      return res.status(401).json({ error: 'Authentication failed' });
    }
  };
}

/**
 * Express middleware that requires all specified roles.
 * Use when a route needs admin AND manager access simultaneously.
 */
export function requireAllRoles(auth: AuthService, roles: string[]) {
  return authMiddleware(auth, [], {
    optional: false,
  });
}

/**
 * Rate-limit aware auth middleware that adds token metadata to response headers.
 */
export function authWithHeaders(auth: AuthService) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.substring(7);

    try {
      const payload = auth.verifyAccessToken(token);
      req.user = payload;

      // Add token metadata headers
      if (payload.exp) {
        res.setHeader('X-Token-Expires', new Date(payload.exp * 1000).toISOString());
      }
      res.setHeader('X-Token-Subject', payload.sub || '');

      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}
