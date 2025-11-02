# Security Best Practices in Web Development

## Table of Contents
1. [Introduction](#introduction)
2. [Authentication and Authorization](#authentication-and-authorization)
3. [Input Validation and Sanitization](#input-validation-and-sanitization)
4. [Secure Communication](#secure-communication)
5. [Data Protection](#data-protection)
6. [Error Handling](#error-handling)
7. [CSRF Protection](#csrf-protection)
8. [CORS (Cross-Origin Resource Sharing)](#cors-cross-origin-resource-sharing)
9. [Content Security Policy (CSP)](#content-security-policy-csp)
10. [Security Headers](#security-headers)
11. [Third-Party Libraries and Dependencies](#third-party-libraries-and-dependencies)
12. [Regular Security Audits](#regular-security-audits)
13. [Conclusion](#conclusion)

## Introduction

Web security is a critical aspect of web development. Ensuring that your web application is secure helps protect user data, maintain trust, and prevent unauthorized access. This document outlines best practices for securing web applications.

## Authentication and Authorization

- **Use Strong Passwords**: Enforce strong password policies and consider using password managers.
- **Multi-Factor Authentication (MFA)**: Implement MFA to add an extra layer of security.
- **Session Management**: Use secure, HTTP-only cookies for session management.
- **Role-Based Access Control (RBAC)**: Implement RBAC to ensure users have the minimum necessary permissions.

### Code Examples

**Password Hashing with bcrypt (Node.js)**
```javascript
const bcrypt = require('bcrypt');

// Hash password
async function hashPassword(plainPassword) {
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
  return hashedPassword;
}

// Verify password
async function verifyPassword(plainPassword, hashedPassword) {
  const match = await bcrypt.compare(plainPassword, hashedPassword);
  return match;
}
```

**Secure Session Cookie Configuration (Express.js)**
```javascript
const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,        // Only send over HTTPS
    httpOnly: true,      // Prevent XSS attacks
    maxAge: 3600000,     // 1 hour
    sameSite: 'strict'   // CSRF protection
  }
}));
```

**Role-Based Access Control Middleware**
```javascript
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    next();
  };
}

// Usage
app.delete('/api/users/:id', requireRole('admin'), deleteUser);
```

## Input Validation and Sanitization

- **Validate Input**: Always validate user input on both the client and server sides.
- **Sanitize Input**: Sanitize input to prevent injection attacks (e.g., SQL injection, XSS).
- **Use Parameterized Queries**: Avoid dynamic SQL queries; use parameterized queries or prepared statements.

### Code Examples

**Input Validation (Express.js with express-validator)**
```javascript
const { body, validationResult } = require('express-validator');

app.post('/api/users', [
  body('email').isEmail().normalizeEmail(),
  body('username').isAlphanumeric().isLength({ min: 3, max: 20 }),
  body('age').optional().isInt({ min: 0, max: 120 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  // Process valid input
  // ...
});
```

**XSS Prevention with HTML Sanitization**
```javascript
const DOMPurify = require('isomorphic-dompurify');

function sanitizeHTML(dirtyHTML) {
  return DOMPurify.sanitize(dirtyHTML, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
    ALLOWED_ATTR: ['href']
  });
}

// Usage
const userInput = req.body.comment;
const cleanHTML = sanitizeHTML(userInput);
```

**SQL Injection Prevention with Parameterized Queries**
```javascript
// BAD - Vulnerable to SQL injection
const userId = req.params.id;
const query = `SELECT * FROM users WHERE id = ${userId}`;

// GOOD - Using parameterized queries
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId], (err, results) => {
  // Handle results
});

// Even better - Using ORM (e.g., Sequelize)
const user = await User.findByPk(userId);
```

## Secure Communication

- **HTTPS**: Use HTTPS to encrypt data in transit.
- **SSL/TLS Certificates**: Ensure your SSL/TLS certificates are up-to-date and from trusted Certificate Authorities (CAs).
- **HSTS**: Implement HTTP Strict Transport Security (HSTS) to enforce HTTPS.

### Code Examples

**Force HTTPS Redirect (Express.js)**
```javascript
function requireHTTPS(req, res, next) {
  if (!req.secure && req.get('x-forwarded-proto') !== 'https') {
    return res.redirect('https://' + req.get('host') + req.url);
  }
  next();
}

// Apply to all routes
app.use(requireHTTPS);
```

**HSTS Configuration**
```javascript
const helmet = require('helmet');

app.use(helmet.hsts({
  maxAge: 31536000,           // 1 year in seconds
  includeSubDomains: true,
  preload: true
}));
```

**TLS Configuration (Node.js HTTPS Server)**
```javascript
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('path/to/private-key.pem'),
  cert: fs.readFileSync('path/to/certificate.pem'),
  minVersion: 'TLSv1.2',
  ciphers: [
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES128-SHA256',
    'ECDHE-RSA-AES256-SHA384'
  ].join(':')
};

https.createServer(options, app).listen(443);
```

## Data Protection

- **Encrypt Sensitive Data**: Encrypt sensitive data both in transit and at rest.
- **Secure Storage**: Use secure storage solutions for sensitive information.
- **Backup and Recovery**: Regularly back up data and have a recovery plan in place.

### Code Examples

**Data Encryption at Rest (Node.js)**
```javascript
const crypto = require('crypto');

// Encryption
function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

// Decryption
function decrypt(text, key) {
  const parts = text.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = parts.join(':');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Usage
const encryptionKey = process.env.ENCRYPTION_KEY; // 32-byte hex string
const sensitiveData = 'user credit card: 1234-5678-9012-3456';
const encrypted = encrypt(sensitiveData, encryptionKey);
```

**Environment Variable Management**
```javascript
// .env file (NEVER commit this to version control)
// Add .env to .gitignore
DB_PASSWORD=your_secure_password
API_KEY=your_api_key
ENCRYPTION_KEY=64_character_hex_string

// Load in application
require('dotenv').config();

const dbPassword = process.env.DB_PASSWORD;
```

**Secure Data Deletion**
```javascript
// Overwrite sensitive data before deletion
function secureDelete(sensitiveObject) {
  for (let key in sensitiveObject) {
    if (typeof sensitiveObject[key] === 'string') {
      sensitiveObject[key] = '0'.repeat(sensitiveObject[key].length);
    }
    delete sensitiveObject[key];
  }
}
```

## Error Handling

- **Generic Error Messages**: Avoid exposing stack traces or database errors to users.
- **Logging**: Implement proper logging and monitoring to detect and respond to security incidents.
- **Rate Limiting**: Implement rate limiting to prevent brute-force attacks.

### Code Examples

**Secure Error Handling Middleware**
```javascript
// Development vs Production error handling
app.use((err, req, res, next) => {
  // Log the full error for debugging
  console.error(err.stack);

  // Send generic error to client
  if (process.env.NODE_ENV === 'production') {
    res.status(err.status || 500).json({
      error: 'An error occurred',
      message: 'Please try again later'
    });
  } else {
    // Only in development: include stack trace
    res.status(err.status || 500).json({
      error: err.message,
      stack: err.stack
    });
  }
});
```

**Rate Limiting**
```javascript
const rateLimit = require('express-rate-limit');

// General API rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Stricter limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 login attempts per 15 minutes
  skipSuccessfulRequests: true
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
```

**Secure Logging with Winston**
```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Log security events
function logSecurityEvent(event, details) {
  logger.warn('Security Event', {
    event,
    details,
    timestamp: new Date().toISOString(),
    ip: details.ip || 'unknown'
  });
}

// Usage
logSecurityEvent('failed_login', {
  username: req.body.username,
  ip: req.ip
});
```

## CSRF Protection

Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to submit a request to a Web application against which they are currently authenticated. CSRF attacks exploit the trust that a site has in a user's browser.

### Best Practices

- **Use CSRF Tokens**: Implement CSRF tokens for all state-changing operations.
- **SameSite Cookie Attribute**: Set the SameSite attribute on cookies to prevent them from being sent with cross-site requests.
- **Verify Origin Headers**: Check the Origin and Referer headers on requests.
- **Use Anti-CSRF Libraries**: Leverage well-tested libraries for CSRF protection.

### Code Examples

**CSRF Protection with csurf (Express.js)**
```javascript
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

// Setup CSRF protection middleware
const csrfProtection = csrf({ cookie: true });

app.use(cookieParser());

// Apply to routes that need protection
app.get('/form', csrfProtection, (req, res) => {
  // Pass token to template
  res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/process', csrfProtection, (req, res) => {
  res.send('Data is being processed');
});
```

**HTML Form with CSRF Token**
```html
<form action="/process" method="POST">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>">
  <input type="text" name="username">
  <button type="submit">Submit</button>
</form>
```

**CSRF Token in AJAX Request**
```javascript
// Get CSRF token from meta tag
const token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

// Include in fetch request
fetch('/api/update', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'CSRF-Token': token
  },
  body: JSON.stringify({ data: 'value' })
});
```

**Double Submit Cookie Pattern**
```javascript
const crypto = require('crypto');

function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Set CSRF token as cookie and require it in request body
app.use((req, res, next) => {
  if (!req.cookies.csrfToken) {
    const token = generateCSRFToken();
    res.cookie('csrfToken', token, {
      httpOnly: false, // Needs to be accessible to JavaScript
      sameSite: 'strict'
    });
  }
  next();
});

// Verification middleware
function verifyCSRF(req, res, next) {
  const tokenFromCookie = req.cookies.csrfToken;
  const tokenFromBody = req.body.csrfToken || req.headers['x-csrf-token'];

  if (!tokenFromCookie || !tokenFromBody || tokenFromCookie !== tokenFromBody) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}
```

## CORS (Cross-Origin Resource Sharing)

CORS is a security mechanism that allows or restricts resources on a web server to be requested from another domain outside the domain from which the resource originated.

### Best Practices

- **Whitelist Specific Origins**: Never use `*` for Access-Control-Allow-Origin in production.
- **Limit Allowed Methods**: Only allow necessary HTTP methods.
- **Control Credentials**: Be cautious when allowing credentials with CORS.
- **Validate Origin**: Always validate the origin before setting CORS headers.

### Code Examples

**Basic CORS Configuration (Express.js)**
```javascript
const cors = require('cors');

// Simple usage - Allow all origins (NOT recommended for production)
app.use(cors());

// Recommended: Configure allowed origins
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://yourdomain.com',
      'https://www.yourdomain.com'
    ];

    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));
```

**Manual CORS Headers**
```javascript
app.use((req, res, next) => {
  const allowedOrigins = ['https://yourdomain.com'];
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});
```

**Route-Specific CORS**
```javascript
// Allow CORS only for specific routes
app.get('/api/public', cors(), (req, res) => {
  res.json({ message: 'This route is publicly accessible' });
});

// Protected route without CORS
app.get('/api/private', (req, res) => {
  res.json({ message: 'This route does not allow CORS' });
});
```

## Content Security Policy (CSP)

Content Security Policy is an added layer of security that helps detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.

### Best Practices

- **Start with a Restrictive Policy**: Begin with a strict policy and gradually relax it as needed.
- **Avoid 'unsafe-inline' and 'unsafe-eval'**: These directives weaken your security posture.
- **Use Nonces or Hashes**: For inline scripts and styles, use nonces or hashes instead of 'unsafe-inline'.
- **Report Violations**: Implement CSP reporting to monitor policy violations.

### Code Examples

**Basic CSP Configuration (Express.js with Helmet)**
```javascript
const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "https://trusted-cdn.com"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    imgSrc: ["'self'", "data:", "https:"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    connectSrc: ["'self'", "https://api.yourdomain.com"],
    frameSrc: ["'none'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}));
```

**CSP with Nonce for Inline Scripts**
```javascript
const crypto = require('crypto');

app.use((req, res, next) => {
  // Generate a nonce for this request
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use(helmet.contentSecurityPolicy({
  directives: {
    scriptSrc: [
      "'self'",
      (req, res) => `'nonce-${res.locals.nonce}'`
    ]
  }
}));

// In your template
// <script nonce="<%= nonce %>">
//   console.log('This inline script is allowed');
// </script>
```

**CSP Reporting**
```javascript
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    reportUri: '/csp-violation-report'
  }
}));

// Endpoint to receive CSP violation reports
app.post('/csp-violation-report', express.json({ type: 'application/csp-report' }), (req, res) => {
  console.log('CSP Violation:', req.body);

  // Log the violation for analysis
  logger.warn('CSP Violation', {
    report: req.body['csp-report'],
    timestamp: new Date().toISOString()
  });

  res.status(204).end();
});
```

**Strict CSP Configuration**
```javascript
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'none'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'"],
    fontSrc: ["'self'"],
    connectSrc: ["'self'"],
    frameSrc: ["'none'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    upgradeInsecureRequests: []
  }
}));
```

## Security Headers

Security headers are HTTP response headers that help protect your web application from common attacks. Proper configuration of these headers is crucial for web security.

### Best Practices

- **Use Helmet.js**: Helmet helps secure Express apps by setting various HTTP headers.
- **X-Frame-Options**: Prevent clickjacking attacks.
- **X-Content-Type-Options**: Prevent MIME-type sniffing.
- **Referrer-Policy**: Control referrer information.
- **Permissions-Policy**: Control browser features and APIs.

### Code Examples

**Comprehensive Security Headers with Helmet**
```javascript
const helmet = require('helmet');

// Use all helmet defaults
app.use(helmet());

// Or configure individually
app.use(helmet({
  // Hide X-Powered-By header
  hidePoweredBy: true,

  // Prevent clickjacking
  frameguard: {
    action: 'deny'
  },

  // Prevent MIME-type sniffing
  noSniff: true,

  // Enable XSS filter (legacy browsers)
  xssFilter: true,

  // HSTS
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
```

**Individual Security Headers**
```javascript
// X-Frame-Options: Prevent clickjacking
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// X-Content-Type-Options: Prevent MIME sniffing
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// X-XSS-Protection (for older browsers)
app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Referrer-Policy: Control referrer information
app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Permissions-Policy: Control browser features
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy',
    'geolocation=(), microphone=(), camera=()');
  next();
});
```

**Complete Security Headers Setup**
```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Apply comprehensive security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://trusted-cdn.com"],
      styleSrc: ["'self'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: {
    action: 'deny'
  },
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));

// Additional custom headers
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy',
    'geolocation=(), microphone=(), camera=()');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  next();
});
```

## Third-Party Libraries and Dependencies

- **Regular Updates**: Keep all third-party libraries and dependencies up-to-date.
- **Vulnerability Scanning**: Use tools to scan for known vulnerabilities in dependencies.
- **Minimal Dependencies**: Use the minimal number of dependencies necessary for your application.

### Code Examples

**Package Vulnerability Scanning**
```bash
# Using npm audit
npm audit

# Fix vulnerabilities automatically
npm audit fix

# Force fix (may introduce breaking changes)
npm audit fix --force

# Using Snyk
npm install -g snyk
snyk test
snyk wizard

# Using yarn
yarn audit
```

**Automated Dependency Updates (package.json)**
```json
{
  "scripts": {
    "check-updates": "npm outdated",
    "update-deps": "npm update",
    "audit": "npm audit"
  },
  "devDependencies": {
    "npm-check-updates": "^16.0.0"
  }
}
```

**GitHub Dependabot Configuration (.github/dependabot.yml)**
```yaml
version: 2
updates:
  # Enable version updates for npm
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "your-username"
    commit-message:
      prefix: "chore"
      include: "scope"

  # Enable security updates
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 5
```

**Lock File Verification**
```bash
# Ensure package-lock.json is committed and not modified
git diff package-lock.json

# Verify integrity
npm ci  # Use in CI/CD instead of npm install

# For yarn
yarn install --frozen-lockfile
```

**Subresource Integrity (SRI) for CDN Resources**
```html
<!-- Include integrity hash for CDN resources -->
<script
  src="https://cdn.example.com/library.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/ux..."
  crossorigin="anonymous">
</script>

<link
  rel="stylesheet"
  href="https://cdn.example.com/styles.css"
  integrity="sha384-9ndCyUa..."
  crossorigin="anonymous">
```

## Regular Security Audits

- **Penetration Testing**: Conduct regular penetration testing to identify and fix vulnerabilities.
- **Code Reviews**: Include security considerations in code reviews.
- **Security Training**: Provide regular security training for developers and staff.

### Code Examples

**Security Testing Tools**
```bash
# OWASP ZAP (Zed Attack Proxy)
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://your-app.com

# Using SQLMap for SQL injection testing
sqlmap -u "https://your-app.com/page?id=1" --batch

# Using Nikto for web server scanning
nikto -h https://your-app.com

# SSL/TLS testing with testssl.sh
./testssl.sh https://your-app.com

# Using Burp Suite (Manual testing tool)
# Professional tool for comprehensive security testing
```

**Automated Security Testing in CI/CD**
```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Run npm audit
        run: npm audit --audit-level=moderate

      - name: Run Snyk Security Scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

      - name: Run OWASP Dependency-Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'your-project'
          path: '.'
          format: 'HTML'

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
```

**Security Code Review Checklist**
```javascript
/**
 * Security Code Review Checklist
 *
 * [ ] Input validation implemented for all user inputs
 * [ ] Parameterized queries used (no string concatenation)
 * [ ] Authentication and authorization checks in place
 * [ ] Sensitive data encrypted at rest and in transit
 * [ ] Error messages don't leak sensitive information
 * [ ] Proper logging of security events
 * [ ] CSRF protection enabled for state-changing operations
 * [ ] XSS prevention measures implemented
 * [ ] Security headers configured
 * [ ] No hardcoded credentials or secrets
 * [ ] Rate limiting implemented on sensitive endpoints
 * [ ] Dependencies are up-to-date and scanned for vulnerabilities
 */

// Example: Security-focused code review comments
function processPayment(userId, amount) {
  // ✅ GOOD: Input validation
  if (!Number.isFinite(amount) || amount <= 0) {
    throw new Error('Invalid amount');
  }

  // ✅ GOOD: Authorization check
  if (!req.user || req.user.id !== userId) {
    throw new Error('Unauthorized');
  }

  // ✅ GOOD: Parameterized query
  const query = 'INSERT INTO payments (user_id, amount) VALUES (?, ?)';
  await db.query(query, [userId, amount]);

  // ✅ GOOD: Security event logging
  logger.info('Payment processed', {
    userId,
    amount,
    timestamp: new Date().toISOString()
  });
}
```

**Penetration Testing Checklist**
```markdown
# Penetration Testing Checklist

## Authentication & Session Management
- [ ] Test for weak password policies
- [ ] Test for session fixation vulnerabilities
- [ ] Test for insecure session handling
- [ ] Test for authentication bypass
- [ ] Test for brute force protection

## Input Validation
- [ ] SQL Injection testing
- [ ] Cross-Site Scripting (XSS) testing
- [ ] Command Injection testing
- [ ] LDAP Injection testing
- [ ] XML Injection testing

## Access Control
- [ ] Test for privilege escalation
- [ ] Test for insecure direct object references
- [ ] Test for missing function level access control

## Security Configuration
- [ ] Test for default credentials
- [ ] Test for misconfigured security headers
- [ ] Test for unnecessary services enabled
- [ ] Test SSL/TLS configuration

## Business Logic
- [ ] Test for business logic flaws
- [ ] Test for race conditions
- [ ] Test for workflow bypass

## API Security
- [ ] Test for broken authentication
- [ ] Test for excessive data exposure
- [ ] Test for lack of rate limiting
- [ ] Test for mass assignment
```

**Security Monitoring Dashboard Setup**
```javascript
// Example: Setting up security monitoring with Prometheus metrics
const prometheus = require('prom-client');

// Create metrics
const loginAttempts = new prometheus.Counter({
  name: 'login_attempts_total',
  help: 'Total number of login attempts',
  labelNames: ['status', 'method']
});

const securityEvents = new prometheus.Counter({
  name: 'security_events_total',
  help: 'Total number of security events',
  labelNames: ['type', 'severity']
});

// Track failed login attempts
app.post('/login', async (req, res) => {
  const result = await authenticateUser(req.body);

  if (result.success) {
    loginAttempts.inc({ status: 'success', method: 'password' });
  } else {
    loginAttempts.inc({ status: 'failure', method: 'password' });
    securityEvents.inc({ type: 'failed_login', severity: 'medium' });
  }

  // ... rest of login logic
});

// Expose metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', prometheus.register.contentType);
  res.end(await prometheus.register.metrics());
});
```

## Conclusion

Implementing these best practices will significantly enhance the security of your web application. Stay informed about the latest security threats and continuously update your security measures to protect against evolving risks.

---

Feel free to contribute to this document by suggesting improvements or adding new best practices.
Big Thanks Happy Coding

