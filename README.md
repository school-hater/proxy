# PondPilot CORS Proxy

A transparent CORS proxy service for PondPilot that enables browser-based access to remote databases and files that don't have CORS headers configured.

## 🌟 Features

- **Privacy-First**: Transparent proxy with no logging or data retention
- **Multiple Deployment Options**: Official hosted service or self-hosted
- **Security**: SSRF protection, domain allowlisting, rate limiting, origin validation
- **Production-Ready**: Built for scale with Cloudflare Workers
- **Open Source**: Full transparency - verify the code yourself

### 🛡️ Version 2.0 Security Enhancements

- **SSRF Protection**: Blocks access to private IPs, localhost, and cloud metadata endpoints
- **Domain Allowlisting**: Only approved public data sources can be proxied
- **Redirect Blocking**: Prevents redirect-based SSRF attacks
- **HTTPS Enforcement**: Production mode requires HTTPS by default
- **Request Timeouts**: Prevents hanging connections (30s default)

## 🏗️ Architecture

This repository provides two deployment options:

### 1. Official Hosted Service (Cloudflare Workers)
- Deployed at `cors-proxy.pondpilot.io`
- Free for PondPilot users
- No setup required
- Serverless architecture with global edge network
- **Code:** `./cloudflare-worker/`

### 2. Self-Hosted (Node.js + Docker)
- Full control and privacy
- Easy Docker deployment
- Can be run on any Node.js hosting
- **Code:** `./self-hosted/`

## 🚀 Quick Start

### Using the Official Service

The official PondPilot CORS proxy is available at:
```
https://cors-proxy.pondpilot.io/proxy?url=<encoded-url>
```

Example:
```bash
curl "https://cors-proxy.pondpilot.io/proxy?url=https%3A%2F%2Fexample.com%2Fdata.duckdb"
```

### Self-Hosting with Docker

```bash
# Clone the repository
git clone https://github.com/yourusername/cors-proxy.git
cd cors-proxy/self-hosted

# Configure (optional)
cp .env.example .env
# Edit .env with your settings

# Run with Docker
docker compose up -d
```

Your proxy will be available at `http://localhost:3000`

## 📖 Detailed Documentation

- [Cloudflare Worker Setup](./cloudflare-worker/README.md) - Deploy your own Cloudflare Worker
- [Self-Hosted Setup](./self-hosted/README.md) - Run on your own infrastructure
- [Security & Privacy](./SECURITY.md) - Security considerations and privacy policy
- [Integration Guide](./INTEGRATION.md) - How to integrate with PondPilot

## 🔒 Security & Privacy

### What This Proxy Does
- Forwards HTTP GET/HEAD requests to the target URL
- Adds CORS headers to allow browser access
- Validates request origins
- Applies rate limiting

### What This Proxy Does NOT Do
- Log request URLs or content
- Store or cache data
- Modify response data
- Track users

### Security Features
- **SSRF Protection**: Blocks private IPs (10.x, 192.168.x, 127.x, 169.254.x) and cloud metadata
- **Domain Allowlisting**: Default allowlist for S3, CloudFront, GitHub, GCS, Azure Blob, CDNs
- **Origin Validation**: Only PondPilot domains allowed
- **Redirect Blocking**: Prevents redirect-based attacks
- **Rate Limiting**: Per-IP limits to prevent abuse (60 req/min default)
- **HTTPS Enforcement**: Production mode is HTTPS-only
- **Request Timeouts**: 30-second timeout prevents hanging
- **No Logging**: No request/response data logged

See [SECURITY.md](./SECURITY.md) for full details.

## 🛠️ Configuration

### Environment Variables

Both deployments support these configuration options:

| Variable | Description | Default |
|----------|-------------|---------|
| `ALLOWED_ORIGINS` | Comma-separated list of allowed origins | `https://app.pondpilot.io` |
| `ALLOWED_DOMAINS` | Domain allowlist (empty = use secure defaults) | `` (secure defaults) |
| `HTTPS_ONLY` | Require HTTPS URLs (auto-enabled in production) | `true` |
| `RATE_LIMIT_REQUESTS` | Max requests per minute per IP | `60` |
| `MAX_FILE_SIZE_MB` | Maximum file size to proxy | `500` |
| `REQUEST_TIMEOUT_MS` | Request timeout in milliseconds | `30000` |
| `SLACK_WEBHOOK_URL` | (Optional) Slack webhook for bug reports | `` (disabled) |

**Default Allowed Domains** (when `ALLOWED_DOMAINS` is empty):
- AWS S3, CloudFront, GitHub, Google Cloud Storage, Azure Blob Storage, Common CDNs

**Custom Allowlist Examples**:
```bash
# Only specific S3 bucket
ALLOWED_DOMAINS=my-bucket.s3.amazonaws.com

# Multiple domains with wildcards
ALLOWED_DOMAINS=*.s3.amazonaws.com,*.cloudfront.net,data.example.com
```

## 📊 Use Cases

This proxy enables PondPilot to:
- Access public DuckDB databases from S3 without CORS
- Load remote CSV/Parquet files for analysis
- Attach public database files hosted anywhere
- Work with any public data source

## 🤝 Contributing

Contributions welcome! Please read our [Contributing Guide](./CONTRIBUTING.md).

## 📜 License

MIT License - see [LICENSE](./LICENSE)

## ⚠️ Disclaimer

This proxy is designed for accessing **public data sources only**. Do not use it to access:
- Private/authenticated resources
- Data you don't have permission to access
- Services that prohibit proxy access in their terms of service

## 🔗 Links

- [PondPilot Website](https://pondpilot.io)
- [PondPilot App](https://app.pondpilot.io)
- [Report Issues](https://github.com/yourusername/cors-proxy/issues)
