/**
 * PondPilot CORS Proxy - Self-Hosted Node.js Server
 *
 * A transparent CORS proxy that enables browser-based access to remote files
 * without CORS headers. Designed for PondPilot to access public data sources.
 *
 * Privacy: No logging, no data retention, no tracking
 * Security: Origin validation, rate limiting, SSRF protection, domain allowlisting
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import {
  validateTargetUrl,
  validateResponse,
  parseAllowedDomains,
  DEFAULT_ALLOWED_DOMAINS,
} from '../shared/security.js';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const config = {
  allowedOrigins: (process.env.ALLOWED_ORIGINS || 'https://app.pondpilot.io,http://localhost:5173')
    .split(',')
    .map(o => o.trim()),
  rateLimitRequests: parseInt(process.env.RATE_LIMIT_REQUESTS || '60'),
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000'), // 1 minute
  maxFileSizeMB: parseInt(process.env.MAX_FILE_SIZE_MB || '500'),
  requestTimeoutMs: parseInt(process.env.REQUEST_TIMEOUT_MS || '30000'), // 30 seconds
  httpsOnly: process.env.HTTPS_ONLY === 'false' ? false : true,
  allowedProtocols: process.env.HTTPS_ONLY === 'false' ? ['https:', 'http:'] : ['https:'],
  allowedDomains: parseAllowedDomains(process.env.ALLOWED_DOMAINS || ''),
  allowCredentials: process.env.ALLOW_CREDENTIALS === 'true',
};

console.log('Configuration:', {
  allowedOrigins: config.allowedOrigins,
  rateLimitRequests: config.rateLimitRequests,
  maxFileSizeMB: config.maxFileSizeMB,
  requestTimeoutMs: config.requestTimeoutMs,
  httpsOnly: config.httpsOnly,
  allowedDomainsCount: config.allowedDomains.length,
  port: PORT,
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// CORS configuration
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests) in development
    if (!origin && process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }

    if (origin && config.allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'HEAD', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Range'],
  exposedHeaders: ['Content-Length', 'Content-Range', 'Content-Type', 'Accept-Ranges', 'ETag', 'Last-Modified'],
  credentials: config.allowCredentials,
  maxAge: 86400,
};

app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitRequests,
  message: { error: 'Rate limit exceeded. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/proxy-path', limiter);

// Request logging (only in development)
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`, {
      origin: req.headers.origin,
      ip: req.ip,
    });
    next();
  });
}

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'pondpilot-cors-proxy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// Info endpoint
app.get(['/', '/info'], (req: Request, res: Response) => {
  res.json({
    service: 'PondPilot CORS Proxy (Self-Hosted)',
    version: '2.1.1',
    usage: 'GET /proxy?url=<encoded-url>',
    privacy: 'No logging, no data retention',
    security: 'SSRF protection, domain allowlisting, HTTPS enforcement',
    source: 'https://github.com/pondpilot/cors-proxy',
    config: {
      allowedOrigins: config.allowedOrigins,
      rateLimitRequests: config.rateLimitRequests,
      maxFileSizeMB: config.maxFileSizeMB,
      httpsOnly: config.httpsOnly,
      allowedDomainsCount: config.allowedDomains.length,
      usingDefaultAllowlist: !process.env.ALLOWED_DOMAINS,
    },
  });
});

// OPTIONS handler for CORS preflight requests
app.options('/proxy-path/:protocol/:host/*', (req: Request, res: Response) => {
  const origin = req.headers.origin;
  if (origin && config.allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Range');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Content-Type, Accept-Ranges, ETag, Last-Modified');
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
    res.setHeader('Vary', 'Origin');
  }
  res.sendStatus(204);
});

// Path-based proxy endpoint for DuckDB compatibility
// Supports URLs like: /proxy-path/https/bucket.s3.amazonaws.com/file.duckdb
// This allows DuckDB to append .wal and other extensions correctly
app.get('/proxy-path/:protocol/:host/*', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { protocol, host } = req.params;
    const path = req.params[0] || '';

    // Security: Validate protocol to prevent protocol injection attacks
    const allowedProtocols = ['http', 'https'];
    if (!allowedProtocols.includes(protocol.toLowerCase())) {
      return res.status(400).json({
        error: 'Invalid protocol. Only http and https are allowed.'
      });
    }

    // Security: Validate host against internal/private networks (SSRF protection)
    // Block localhost, private networks, and other internal addresses
    const internalHostPatterns = [
      /^localhost$/i,
      /^127\./,                          // Loopback
      /^10\./,                           // Private network
      /^172\.(1[6-9]|2[0-9]|3[01])\./,  // Private network
      /^192\.168\./,                     // Private network
      /^169\.254\./,                     // Link-local
      /^::1$/,                           // IPv6 loopback
      /^fe80:/i,                         // IPv6 link-local
      /^fc00:/i,                         // IPv6 unique local
      /^metadata\.google\.internal$/i,  // Cloud metadata
      /^169\.254\.169\.254$/,           // AWS metadata
    ];

    if (internalHostPatterns.some(pattern => pattern.test(host))) {
      return res.status(403).json({
        error: 'Access to internal/private addresses is not allowed.'
      });
    }

    // Security: Sanitize path to prevent path traversal attacks
    const sanitizedPath = path
      .replace(/\.\./g, '')      // Remove path traversal sequences
      .replace(/\/+/g, '/')      // Normalize multiple slashes
      .replace(/^\//, '');       // Remove leading slash (already in URL template)

    // Reconstruct the target URL with sanitized components
    const targetUrl = `${protocol}://${host}/${sanitizedPath}`;

    // Set CORS headers FIRST before any other processing
    const origin = req.headers.origin;
    if (origin && config.allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Range');
      res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Content-Type, Accept-Ranges, ETag, Last-Modified');
      res.setHeader('Vary', 'Origin');
    }

    // Validate URL with SSRF protection
    const validation = validateTargetUrl(targetUrl, {
      allowedDomains: config.allowedDomains,
      allowedProtocols: config.allowedProtocols,
      httpsOnly: config.httpsOnly,
      maxFileSizeMB: config.maxFileSizeMB,
    });

    if (!validation.valid) {
      return res.status(403).json({ error: validation.error });
    }

    // Fetch the resource with timeout and no redirect following
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.requestTimeoutMs);

    let fetchResponse: globalThis.Response;
    try {
      // Prepare headers for upstream request
      const upstreamHeaders: Record<string, string> = {
        'User-Agent': 'PondPilot-CORS-Proxy/2.1',
      };

      // Forward Range header if present (required for DuckDB random-access reads)
      const rangeHeader = req.headers.range;
      if (rangeHeader) {
        upstreamHeaders['Range'] = rangeHeader;
      }

      fetchResponse = await fetch(targetUrl, {
        method: req.method,
        headers: upstreamHeaders,
        redirect: 'manual', // Critical: Prevent redirects to internal IPs
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    // Validate response (check for redirects, file size)
    const responseValidation = validateResponse(fetchResponse, config.maxFileSizeMB);
    if (!responseValidation.valid) {
      return res.status(400).json({ error: responseValidation.error });
    }

    const maxBytes = config.maxFileSizeMB * 1024 * 1024;
    let transferred = 0;
    let startedStreaming = false;

    // Copy headers from upstream
    const headersToForward = [
      'content-type',
      'content-range',
      'content-length',
      'accept-ranges',
      'etag',
      'last-modified',
    ];

    headersToForward.forEach(header => {
      const value = fetchResponse.headers.get(header);
      if (value) {
        res.setHeader(header, value);
      }
    });

    // Add proxy headers
    res.setHeader('X-Proxy-By', 'PondPilot-CORS-Proxy');
    res.setHeader('Cache-Control', 'public, max-age=3600');

    // Set status
    res.status(fetchResponse.status);

    // Stream the response
    if (fetchResponse.body) {
      const reader = fetchResponse.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        if (!value) {
          continue;
        }

        if (transferred + value.byteLength > maxBytes) {
          await reader.cancel('File too large');
          console.warn(`Aborting response over size limit from ${targetUrl}`, {
            limitMB: config.maxFileSizeMB,
            transferredMB: (transferred / (1024 * 1024)).toFixed(1),
          });

          if (!startedStreaming) {
            headersToForward.forEach(header => res.removeHeader(header));
            res.setHeader('Cache-Control', 'no-store');
            return res.status(413).json({
              error: `File too large (${((transferred + value.byteLength) / (1024 * 1024)).toFixed(1)}MB exceeds limit of ${config.maxFileSizeMB}MB)`,
            });
          }

          res.setHeader('Connection', 'close');
          res.destroy(new Error('File too large'));
          return;
        }

        transferred += value.byteLength;
        res.write(value);
        startedStreaming = true;
      }
      res.end();
    } else {
      res.end();
    }

  } catch (error) {
    // Handle timeout errors
    if (error instanceof Error && error.name === 'AbortError') {
      return res.status(504).json({
        error: 'Request timeout - the remote server took too long to respond',
      });
    }

    console.error('Proxy error:', error);
    res.status(502).json({
      error: `Failed to fetch resource: ${error instanceof Error ? error.message : 'Unknown error'}`,
    });
  }
});

// Bug report endpoint - POST to Slack webhook
app.post('/bug-report', express.json(), async (req: Request, res: Response) => {
  const origin = req.headers.origin;

  // Validate origin
  if (!origin || !config.allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }

  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Check if webhook URL is configured
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;
  if (!webhookUrl) {
    return res.status(503).json({ error: 'Bug reporting is not configured on this server' });
  }

  // Validate webhook URL is actually a Slack webhook
  if (!webhookUrl.startsWith('https://hooks.slack.com/')) {
    console.error('Invalid SLACK_WEBHOOK_URL configured:', webhookUrl);
    return res.status(500).json({ error: 'Server configuration error' });
  }

  try {
    const { slackPayload } = req.body;

    if (!slackPayload) {
      return res.status(400).json({ error: 'Missing slackPayload' });
    }

    // Forward to Slack
    const slackResponse = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(slackPayload),
    });

    const responseText = await slackResponse.text();

    return res.status(slackResponse.ok ? 200 : 500).json({
      success: slackResponse.ok,
      status: slackResponse.status,
      message: responseText,
    });
  } catch (error) {
    console.error('Bug report error:', error);
    return res.status(500).json({
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// OPTIONS handler for bug report endpoint
app.options('/bug-report', (req: Request, res: Response) => {
  const origin = req.headers.origin;
  if (origin && config.allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  res.sendStatus(204);
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not found. Use /proxy-path/<protocol>/<host>/<path>',
  });
});

// Error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err.message);

  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Origin not allowed' });
  }

  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 PondPilot CORS Proxy running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔒 Allowed origins:`, config.allowedOrigins);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  process.exit(0);
});
