import { Response } from 'node-fetch';

// Define specific error types for different scenarios
export enum CoinbaseErrorType {
  AUTHENTICATION = 'AUTHENTICATION',
  PERMISSION = 'PERMISSION',
  VALIDATION = 'VALIDATION',
  RATE_LIMIT = 'RATE_LIMIT',
  SERVER_ERROR = 'SERVER_ERROR',
  NETWORK_ERROR = 'NETWORK_ERROR',
  UNKNOWN = 'UNKNOWN'
}

export interface CoinbaseErrorDetails {
  type: CoinbaseErrorType;
  message: string;
  details?: Record<string, any>;
  suggestion?: string;
}

export class CoinbaseError extends Error {
  readonly statusCode: number;
  readonly response: Response;
  readonly type: CoinbaseErrorType;
  readonly details?: Record<string, any>;
  readonly suggestion?: string;

  constructor(errorDetails: CoinbaseErrorDetails, statusCode: number, response: Response) {
    super(errorDetails.message);
    this.name = 'CoinbaseError';
    this.statusCode = statusCode;
    this.response = response;
    this.type = errorDetails.type;
    this.details = errorDetails.details;
    this.suggestion = errorDetails.suggestion;
  }
}

function parseErrorResponse(responseText: string): Record<string, any> {
  if (!responseText) {
    return {
      error: 'Empty response',
      originalResponse: responseText
    };
  }

  try {
    return JSON.parse(responseText);
  } catch (error) {
    // Create a more informative error object for debugging
    return {
      error: 'Invalid JSON response',
      message: error instanceof Error ? error.message : 'Unknown parsing error',
      originalResponse: responseText.slice(0, 200) // Include truncated response for debugging
    };
  }
}

// Sanitize error messages to prevent sensitive information exposure
function sanitizeErrorMessage(message: string): string {
  if (typeof message !== 'string') return '';
  
  // Remove potential sensitive patterns (API keys, tokens, credentials)
  return message
    .replace(/([A-Za-z0-9+/]{32,})/g, '[REDACTED]')
    .replace(/key-[a-zA-Z0-9]{32,}/g, '[REDACTED]')
    .replace(/sk-[a-zA-Z0-9]{32,}/g, '[REDACTED]')
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]');
}

function sanitizeErrorDetails(details: Record<string, any>): Record<string, any> {
  if (!details || typeof details !== 'object') return {};

  const sensitiveKeys = ['apiKey', 'secret', 'token', 'password', 'credential', 'key', 'auth'];
  
  return Object.entries(details).reduce((acc, [key, value]) => {
    // Check if the key contains any sensitive patterns
    if (sensitiveKeys.some(k => key.toLowerCase().includes(k))) {
      acc[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      acc[key] = sanitizeErrorDetails(value);
    } else if (typeof value === 'string') {
      acc[key] = sanitizeErrorMessage(value);
    } else {
      acc[key] = value;
    }
    return acc;
  }, {} as Record<string, any>);
}

function getErrorDetails(response: Response, responseText: string): CoinbaseErrorDetails {
  const parsedError = parseErrorResponse(responseText);
  const status = response.status;

  // Authentication errors
  if (status === 401) {
    return {
      type: CoinbaseErrorType.AUTHENTICATION,
      message: 'Invalid API credentials',
      suggestion: 'Please verify your API key and secret are correct and not expired.'
    };
  }

  // Permission errors
  if (status === 403) {
    if (responseText.includes('"error_details":"Missing required scopes"')) {
      return {
        type: CoinbaseErrorType.PERMISSION,
        message: 'Missing required API permissions',
        suggestion: 'Please verify your API key has the necessary permissions enabled in your Coinbase account settings.'
      };
    }
    return {
      type: CoinbaseErrorType.PERMISSION,
      message: 'Access denied',
      suggestion: 'Please check if you have the necessary permissions to perform this action.'
    };
  }

  // Validation errors
  if (status === 400) {
    return {
      type: CoinbaseErrorType.VALIDATION,
      message: sanitizeErrorMessage(parsedError.message || 'Invalid request parameters'),
      details: sanitizeErrorDetails(parsedError),
      suggestion: 'Please verify all required parameters are provided and have valid values.'
    };
  }

  // Rate limit errors
  if (status === 429) {
    return {
      type: CoinbaseErrorType.RATE_LIMIT,
      message: 'Rate limit exceeded',
      suggestion: 'Please reduce your request frequency or wait before trying again.'
    };
  }

  // Server errors
  if (status >= 500) {
    return {
      type: CoinbaseErrorType.SERVER_ERROR,
      message: 'Coinbase service error',
      suggestion: 'This is a temporary issue with Coinbase. Please try again later.'
    };
  }

  // Default unknown error
  return {
    type: CoinbaseErrorType.UNKNOWN,
    message: sanitizeErrorMessage(`Unexpected error: ${response.statusText}`),
    details: sanitizeErrorDetails(parsedError),
    suggestion: 'If this persists, please contact support with the error details.'
  };
}

export function handleException(
  response: Response,
  responseText: string,
  reason: string
) {
  if ((400 <= response.status && response.status <= 499) ||
      (500 <= response.status && response.status <= 599)) {
    const errorDetails = getErrorDetails(response, responseText);
    // Ensure all error information is sanitized
    errorDetails.message = sanitizeErrorMessage(errorDetails.message);
    if (errorDetails.details) {
      errorDetails.details = sanitizeErrorDetails(errorDetails.details);
    }
    throw new CoinbaseError(errorDetails, response.status, response);
  }
}
