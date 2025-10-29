/**
 * PondPilot CORS Proxy - Cloudflare Worker
 *
 * A transparent CORS proxy that enables browser-based access to remote files
 * without CORS headers. Designed for PondPilot to access public data sources.
 *
 * Privacy: No logging, no data retention, no tracking
 * Security: SSRF protection, domain allowlisting, HTTPS enforcement
 */

import { parseAllowedDomains, validatePatternComplexity, DEFAULT_ALLOWED_DOMAINS } from '../shared/security';

interface Env {
  RATE_LIMITER?: {
    limit: (options: { key: string }) => Promise<{ success: boolean }>;
  };
  ALLOWED_ORIGINS?: string;
  RATE_LIMIT_REQUESTS?: string;
  MAX_FILE_SIZE_MB?: string;
  ALLOWED_DOMAINS?: string;
  HTTPS_ONLY?: string;
  REQUEST_TIMEOUT_MS?: string;
  ALLOW_CREDENTIALS?: string;
  SLACK_WEBHOOK_URL?: string;
}

// Security: Private/internal IP patterns to block (SSRF protection)
const PRIVATE_IP_PATTERNS = [
  /^127\./,                    // 127.0.0.0/8 - Loopback
  /^10\./,                     // 10.0.0.0/8 - Private
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12 - Private
  /^192\.168\./,               // 192.168.0.0/16 - Private
  /^169\.254\./,               // 169.254.0.0/16 - Link-local (AWS metadata!)
  /^0\./,                      // 0.0.0.0/8
  /^224\./,                    // Multicast
  /^240\./,                    // Reserved
  /^::1$/,                     // IPv6 loopback
  /^fe80:/,                    // IPv6 link-local
  /^fc00:/,                    // IPv6 private
  /^fd00:/,                    // IPv6 private
];

const BLOCKED_HOSTNAMES = [
  'localhost',
  '0.0.0.0',
  'metadata.google.internal',  // GCP metadata
];

const DEFAULT_CONFIG = {
  allowedOrigins: ['https://app.pondpilot.io', 'http://localhost:5173', 'http://localhost:3000'],
  rateLimitRequests: 60,
  maxFileSizeMB: 500,
  requestTimeoutMs: 30000,
  allowedProtocols: ['https:'],
  httpsOnly: true,
  allowedDomains: DEFAULT_ALLOWED_DOMAINS,
  allowCredentials: false,
};

// Security validation functions
function isPrivateIP(hostname: string): boolean {
  if (BLOCKED_HOSTNAMES.includes(hostname.toLowerCase())) {
    return true;
  }
  return PRIVATE_IP_PATTERNS.some(pattern => pattern.test(hostname));
}

function isAllowedDomain(hostname: string, allowedDomains: RegExp[]): boolean {
  const lowerHostname = hostname.toLowerCase();
  return allowedDomains.some(pattern => pattern.test(lowerHostname));
}

function validateTargetUrl(targetUrl: string, config: any): { valid: boolean; error?: string } {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch (e) {
    return { valid: false, error: 'Invalid URL format' };
  }

  if (!config.allowedProtocols.includes(parsed.protocol)) {
    return { valid: false, error: `Protocol ${parsed.protocol} not allowed` };
  }

  if (config.httpsOnly && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only HTTPS URLs are allowed' };
  }

  if (isPrivateIP(parsed.hostname)) {
    return { valid: false, error: 'Access to private/internal IP addresses is not allowed' };
  }

  if (!isAllowedDomain(parsed.hostname, config.allowedDomains)) {
    return { valid: false, error: `Domain ${parsed.hostname} is not in the allowlist` };
  }

  return { valid: true };
}

function validateResponse(response: Response, maxFileSizeMB: number): { valid: boolean; error?: string } {
  if (response.status >= 300 && response.status < 400) {
    return { valid: false, error: 'Redirects are not supported for security reasons' };
  }

  const contentLength = response.headers.get('Content-Length');
  if (contentLength) {
    const sizeMB = parseInt(contentLength) / (1024 * 1024);
    if (sizeMB > maxFileSizeMB) {
      return { valid: false, error: `File too large (${sizeMB.toFixed(1)}MB > ${maxFileSizeMB}MB)` };
    }
  }

  return { valid: true };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return handlePreflight(request, env);
    }

    // Bug report endpoint (for PondPilot bug reporting to Slack) - allows POST
    if (url.pathname === '/bug-report') {
      return handleBugReport(request, env);
    }

    // Only allow GET and HEAD for other endpoints
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return jsonError('Method not allowed', 405);
    }

    // Health check endpoint
    if (url.pathname === '/health') {
      return jsonResponse({ status: 'ok', service: 'pondpilot-cors-proxy' });
    }

    // Info endpoint
    if (url.pathname === '/' || url.pathname === '/info') {
      const config = getConfig(env);
      return jsonResponse({
        service: 'PondPilot CORS Proxy (Cloudflare Workers)',
        version: '2.1.1',
        usage: 'GET /proxy?url=<encoded-url> or GET /proxy-path/<protocol>/<host>/<path>',
        privacy: 'No logging, no data retention',
        security: 'SSRF protection, domain allowlisting, HTTPS enforcement',
        source: 'https://github.com/pondpilot/cors-proxy',
        config: {
          httpsOnly: config.httpsOnly,
          allowedDomainsCount: config.allowedDomains.length,
          usingDefaultAllowlist: !env.ALLOWED_DOMAINS,
        },
      });
    }

    // Path-based proxy endpoint for DuckDB compatibility
    // Supports URLs like: /proxy-path/https/bucket.s3.amazonaws.com/file.duckdb
    if (url.pathname.startsWith('/proxy-path/')) {
      return handleProxyPath(request, env, ctx);
    }

    // Proxy endpoint
    if (url.pathname === '/proxy') {
      return handleProxy(request, env, ctx);
    }

    return jsonError('Not found. Use /proxy?url=<encoded-url> or /proxy-path/<protocol>/<host>/<path>', 404);
  },
};

async function handleProxy(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const config = getConfig(env);
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const origin = request.headers.get('Origin');

  // Validate origin
  if (!origin || !config.allowedOrigins.includes(origin)) {
    return corsError('Origin not allowed', origin, 403);
  }

  // Rate limiting
  if (env.RATE_LIMITER) {
    const rateLimitKey = `ip:${clientIP}`;
    const { success } = await env.RATE_LIMITER.limit({ key: rateLimitKey });
    if (!success) {
      return corsError('Rate limit exceeded', origin, 429);
    }
  }

  // Get target URL
  const url = new URL(request.url);
  const targetUrl = url.searchParams.get('url');

  if (!targetUrl) {
    return corsError('Missing url parameter', origin, 400);
  }

  // Validate URL with SSRF protection
  const validation = validateTargetUrl(targetUrl, config);
  if (!validation.valid) {
    return corsError(validation.error || 'Invalid URL', origin, 403);
  }

  // Fetch the resource with security settings
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.requestTimeoutMs);

    let targetResponse: Response;
    try {
      // Prepare headers for upstream request
      const upstreamHeaders: Record<string, string> = {
        'User-Agent': 'PondPilot-CORS-Proxy/2.1',
      };

      // Forward Range header if present (required for DuckDB random-access reads)
      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        upstreamHeaders['Range'] = rangeHeader;
      }

      targetResponse = await fetch(targetUrl, {
        method: request.method,
        headers: upstreamHeaders,
        redirect: 'manual', // Critical: Prevent redirects to internal IPs
        signal: controller.signal,
        // Use Cloudflare's cache
        cf: {
          cacheEverything: true,
          cacheTtl: 3600,
        },
      });
    } finally {
      clearTimeout(timeoutId);
    }

    // Validate response (check for redirects, file size)
    const responseValidation = validateResponse(targetResponse, config.maxFileSizeMB);
    if (!responseValidation.valid) {
      return corsError(responseValidation.error || 'Invalid response', origin, 400);
    }

    // Create response with CORS headers
    const responseHeaders = new Headers();

    // Copy safe headers from upstream (excluding hop-by-hop and security headers)
    const hopByHopHeaders = [
      'connection',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailers',
      'transfer-encoding',
      'upgrade',
    ];

    // Headers that should not be forwarded from upstream to prevent security issues
    const blockedHeaders = [
      'set-cookie',
      'set-cookie2',
      'content-security-policy',
      'content-security-policy-report-only',
      'x-frame-options',
      'cross-origin-resource-policy',
      'permissions-policy',
      'report-to',
      'nel',
      'referrer-policy',
      'origin-agent-cluster',
    ];

    targetResponse.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      if (!hopByHopHeaders.includes(lowerKey) && !blockedHeaders.includes(lowerKey)) {
        responseHeaders.set(key, value);
      }
    });

    // Add CORS headers
    responseHeaders.set('Access-Control-Allow-Origin', origin);
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Range');
    responseHeaders.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Content-Type, Accept-Ranges, ETag, Last-Modified');

    if (config.allowCredentials) {
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');
    }

    // Add Vary headers for proper caching with CORS
    responseHeaders.append('Vary', 'Origin');

    // Add cache headers only if upstream didn't provide them
    if (!responseHeaders.has('Cache-Control')) {
      responseHeaders.set('Cache-Control', 'public, max-age=3600');
    }

    // Add proxy headers for transparency
    responseHeaders.set('X-Proxy-By', 'PondPilot-CORS-Proxy');

    // Stream response with size enforcement
    const maxBytes = config.maxFileSizeMB * 1024 * 1024;
    let bytesTransferred = 0;

    const sizeEnforcingStream = new TransformStream({
      transform(chunk, controller) {
        bytesTransferred += chunk.byteLength;

        if (bytesTransferred > maxBytes) {
          controller.error(new Error(`File too large (exceeds ${config.maxFileSizeMB}MB limit)`));
          return;
        }

        controller.enqueue(chunk);
      },
    });

    // Pipe the response through the size-enforcing stream
    const responseBody = targetResponse.body?.pipeThrough(sizeEnforcingStream);

    return new Response(responseBody, {
      status: targetResponse.status,
      statusText: targetResponse.statusText,
      headers: responseHeaders,
    });

  } catch (error) {
    // Handle timeout errors
    if (error instanceof Error && error.name === 'AbortError') {
      return corsError('Request timeout - the remote server took too long to respond', origin, 504);
    }

    console.error('Fetch error:', error);
    return corsError(`Failed to fetch resource: ${error instanceof Error ? error.message : 'Unknown error'}`, origin, 502);
  }
}

async function handleProxyPath(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const config = getConfig(env);
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const origin = request.headers.get('Origin');

  // Validate origin
  if (!origin || !config.allowedOrigins.includes(origin)) {
    return corsError('Origin not allowed', origin, 403);
  }

  // Rate limiting
  if (env.RATE_LIMITER) {
    const rateLimitKey = `ip:${clientIP}`;
    const { success } = await env.RATE_LIMITER.limit({ key: rateLimitKey });
    if (!success) {
      return corsError('Rate limit exceeded', origin, 429);
    }
  }

  // Parse URL path: /proxy-path/:protocol/:host/*
  const url = new URL(request.url);
  const pathParts = url.pathname.split('/').filter(p => p);

  // pathParts = ['proxy-path', 'https', 'bucket.s3.amazonaws.com', 'file.duckdb']
  if (pathParts.length < 3 || pathParts[0] !== 'proxy-path') {
    return corsError('Invalid path format. Use /proxy-path/<protocol>/<host>/<path>', origin, 400);
  }

  const protocol = pathParts[1];
  const host = pathParts[2];
  const path = pathParts.slice(3).join('/');

  // Security: Validate protocol to prevent protocol injection attacks
  const allowedProtocols = ['http', 'https'];
  if (!allowedProtocols.includes(protocol.toLowerCase())) {
    return corsError('Invalid protocol. Only http and https are allowed.', origin, 400);
  }

  // Security: Validate host against internal/private networks (SSRF protection)
  if (isPrivateIP(host)) {
    return corsError('Access to internal/private addresses is not allowed.', origin, 403);
  }

  // Security: Sanitize path to prevent path traversal attacks
  const sanitizedPath = path
    .replace(/\.\./g, '')      // Remove path traversal sequences
    .replace(/\/+/g, '/')      // Normalize multiple slashes
    .replace(/^\//, '');       // Remove leading slash

  // Reconstruct the target URL with sanitized components
  const targetUrl = `${protocol}://${host}/${sanitizedPath}`;

  // Validate URL with SSRF protection
  const validation = validateTargetUrl(targetUrl, config);
  if (!validation.valid) {
    return corsError(validation.error || 'Invalid URL', origin, 403);
  }

  // Fetch the resource with security settings
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.requestTimeoutMs);

    let targetResponse: Response;
    try {
      // Prepare headers for upstream request
      const upstreamHeaders: Record<string, string> = {
        'User-Agent': 'PondPilot-CORS-Proxy/2.1',
      };

      // Forward Range header if present (required for DuckDB random-access reads)
      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        upstreamHeaders['Range'] = rangeHeader;
      }

      targetResponse = await fetch(targetUrl, {
        method: request.method,
        headers: upstreamHeaders,
        redirect: 'manual', // Critical: Prevent redirects to internal IPs
        signal: controller.signal,
        // Use Cloudflare's cache
        cf: {
          cacheEverything: true,
          cacheTtl: 3600,
        },
      });
    } finally {
      clearTimeout(timeoutId);
    }

    // Validate response (check for redirects, file size)
    const responseValidation = validateResponse(targetResponse, config.maxFileSizeMB);
    if (!responseValidation.valid) {
      return corsError(responseValidation.error || 'Invalid response', origin, 400);
    }

    // Create response with CORS headers
    const responseHeaders = new Headers();

    // Copy safe headers from upstream (excluding hop-by-hop and security headers)
    const hopByHopHeaders = [
      'connection',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailers',
      'transfer-encoding',
      'upgrade',
    ];

    // Headers that should not be forwarded from upstream to prevent security issues
    const blockedHeaders = [
      'set-cookie',
      'set-cookie2',
      'content-security-policy',
      'content-security-policy-report-only',
      'x-frame-options',
      'cross-origin-resource-policy',
      'permissions-policy',
      'report-to',
      'nel',
      'referrer-policy',
      'origin-agent-cluster',
    ];

    targetResponse.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      if (!hopByHopHeaders.includes(lowerKey) && !blockedHeaders.includes(lowerKey)) {
        responseHeaders.set(key, value);
      }
    });

    // Add CORS headers
    responseHeaders.set('Access-Control-Allow-Origin', origin);
    responseHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Range');
    responseHeaders.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Content-Type, Accept-Ranges, ETag, Last-Modified');

    if (config.allowCredentials) {
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');
    }

    // Add Vary headers for proper caching with CORS
    responseHeaders.append('Vary', 'Origin');

    // Add cache headers only if upstream didn't provide them
    if (!responseHeaders.has('Cache-Control')) {
      responseHeaders.set('Cache-Control', 'public, max-age=3600');
    }

    // Add proxy headers for transparency
    responseHeaders.set('X-Proxy-By', 'PondPilot-CORS-Proxy');

    // Stream response with size enforcement
    const maxBytes = config.maxFileSizeMB * 1024 * 1024;
    let bytesTransferred = 0;

    const sizeEnforcingStream = new TransformStream({
      transform(chunk, controller) {
        bytesTransferred += chunk.byteLength;

        if (bytesTransferred > maxBytes) {
          controller.error(new Error(`File too large (exceeds ${config.maxFileSizeMB}MB limit)`));
          return;
        }

        controller.enqueue(chunk);
      },
    });

    // Pipe the response through the size-enforcing stream
    const responseBody = targetResponse.body?.pipeThrough(sizeEnforcingStream);

    return new Response(responseBody, {
      status: targetResponse.status,
      statusText: targetResponse.statusText,
      headers: responseHeaders,
    });

  } catch (error) {
    // Handle timeout errors
    if (error instanceof Error && error.name === 'AbortError') {
      return corsError('Request timeout - the remote server took too long to respond', origin, 504);
    }

    console.error('Fetch error:', error);
    return corsError(`Failed to fetch resource: ${error instanceof Error ? error.message : 'Unknown error'}`, origin, 502);
  }
}

async function handleBugReport(request: Request, env: Env): Promise<Response> {
  const config = getConfig(env);
  const origin = request.headers.get('Origin');

  // Only allow POST
  if (request.method !== 'POST') {
    return corsError('Method not allowed', origin, 405);
  }

  // Validate origin
  if (!origin || !config.allowedOrigins.includes(origin)) {
    return corsError('Origin not allowed', origin, 403);
  }

  // Check if webhook URL is configured on the server
  const webhookUrl = env.SLACK_WEBHOOK_URL;
  if (!webhookUrl) {
    return corsError('Bug reporting is not configured on this server', origin, 503);
  }

  // Validate webhook URL is actually a Slack webhook
  if (!webhookUrl.startsWith('https://hooks.slack.com/')) {
    console.error('Invalid SLACK_WEBHOOK_URL configured:', webhookUrl);
    return corsError('Server configuration error', origin, 500);
  }

  try {
    const body = await request.json() as { slackPayload?: any };
    const { slackPayload } = body;

    if (!slackPayload) {
      return corsError('Missing slackPayload', origin, 400);
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

    return new Response(
      JSON.stringify({
        success: slackResponse.ok,
        status: slackResponse.status,
        message: responseText,
      }),
      {
        status: slackResponse.ok ? 200 : 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': origin,
        },
      }
    );
  } catch (error) {
    return corsError(
      error instanceof Error ? error.message : 'Unknown error',
      origin,
      500
    );
  }
}

function handlePreflight(request: Request, env: Env): Response {
  const config = getConfig(env);
  const origin = request.headers.get('Origin');

  if (!origin || !config.allowedOrigins.includes(origin)) {
    return new Response(null, { status: 403 });
  }

  const url = new URL(request.url);

  // Determine allowed methods based on endpoint
  const allowedMethods = url.pathname === '/bug-report'
    ? 'GET, HEAD, POST, OPTIONS'
    : 'GET, HEAD, OPTIONS';

  const headers: Record<string, string> = {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': allowedMethods,
    'Access-Control-Allow-Headers': 'Content-Type, Range',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Content-Type, Accept-Ranges, ETag, Last-Modified',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers',
  };

  if (config.allowCredentials) {
    headers['Access-Control-Allow-Credentials'] = 'true';
  }

  return new Response(null, { headers });
}

function getConfig(env: Env) {
  return {
    allowedOrigins: env.ALLOWED_ORIGINS
      ? env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
      : DEFAULT_CONFIG.allowedOrigins,
    rateLimitRequests: env.RATE_LIMIT_REQUESTS
      ? parseInt(env.RATE_LIMIT_REQUESTS)
      : DEFAULT_CONFIG.rateLimitRequests,
    maxFileSizeMB: env.MAX_FILE_SIZE_MB
      ? parseInt(env.MAX_FILE_SIZE_MB)
      : DEFAULT_CONFIG.maxFileSizeMB,
    requestTimeoutMs: env.REQUEST_TIMEOUT_MS
      ? parseInt(env.REQUEST_TIMEOUT_MS)
      : DEFAULT_CONFIG.requestTimeoutMs,
    allowedProtocols: DEFAULT_CONFIG.allowedProtocols,
    httpsOnly: env.HTTPS_ONLY === 'false' ? false : DEFAULT_CONFIG.httpsOnly,
    allowedDomains: parseAllowedDomains(env.ALLOWED_DOMAINS),
    allowCredentials: env.ALLOW_CREDENTIALS === 'true',
  };
}

function jsonResponse(data: any, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache',
    },
  });
}

function jsonError(message: string, status: number): Response {
  return jsonResponse({ error: message }, status);
}

function corsError(message: string, origin: string | null, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': origin || '*',
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    },
  });
}
