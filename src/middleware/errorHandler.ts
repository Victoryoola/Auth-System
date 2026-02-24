import { Request, Response, NextFunction } from 'express';

/**
 * Standard error response format
 */
export interface ErrorResponse {
  error: string;
  message: string;
  details?: any;
  statusCode?: number;
}

/**
 * Custom API Error class
 */
export class APIError extends Error {
  statusCode: number;
  errorCode: string;
  details?: any;

  constructor(statusCode: number, errorCode: string, message: string, details?: any) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.name = 'APIError';
  }
}

/**
 * Global error handler middleware
 * Catches all errors and returns consistent error responses
 */
export function errorHandler(
  err: Error | APIError,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  // Log error for debugging
  console.error('Error:', {
    name: err.name,
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  // Handle APIError instances
  if (err instanceof APIError) {
    res.status(err.statusCode).json({
      error: err.errorCode,
      message: err.message,
      details: err.details,
    });
    return;
  }

  // Handle validation errors from express-validator
  if (err.name === 'ValidationError') {
    res.status(400).json({
      error: 'validation_error',
      message: 'Request validation failed',
      details: err.message,
    });
    return;
  }

  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    res.status(401).json({
      error: 'invalid_token',
      message: 'Invalid authentication token',
    });
    return;
  }

  if (err.name === 'TokenExpiredError') {
    res.status(401).json({
      error: 'token_expired',
      message: 'Authentication token has expired',
    });
    return;
  }

  // Handle database errors
  if (err.name === 'QueryFailedError' || err.message.includes('database')) {
    res.status(503).json({
      error: 'database_error',
      message: 'Database operation failed',
    });
    return;
  }

  // Handle rate limit errors
  if (err.message.includes('rate limit') || err.message.includes('Too many requests')) {
    res.status(429).json({
      error: 'rate_limit_exceeded',
      message: 'Too many requests. Please try again later.',
    });
    return;
  }

  // Default to 500 Internal Server Error
  res.status(500).json({
    error: 'internal_server_error',
    message: 'An unexpected error occurred',
  });
}

/**
 * 404 Not Found handler
 * Catches requests to undefined routes
 */
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    error: 'not_found',
    message: `Route ${req.method} ${req.path} not found`,
  });
}

/**
 * Async handler wrapper to catch errors in async route handlers
 * Eliminates need for try-catch in every async route
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
