---
title: "JavaScript Backend Security Best Practices (OWASP Top 10:2025)"
description: "A comprehensive guide to securing your JavaScript backend applications following the OWASP Top 10:2025 guidelines. Covers Bun, Node.js, and Deno with practical code examples."
date: 2026-02-02
category: "Security"
emoji: "🔒"
image: "/images/blog/javascript-security.webp"
draft: false
---

JavaScript is used to build a huge part of the internet's backend systems. Node.js is still the most popular, but newer tools like Bun and Deno are becoming more common because they're faster and have better security built in.

No matter which one you use, the security problems are mostly the same.

This guide shows you how to keep your JavaScript backend safe, following the OWASP Top 10:2025 security guidelines. Everything here works with Bun, Node.js, and Deno.

## TL;DR - Quick Security Checklist

| # | Vulnerability | Quick Fix |
|---|--------------|----------|
| 1 | Broken Access Control | Check permissions server-side, verify resource ownership |
| 2 | Cryptographic Failures | Use bcrypt/argon2, always HTTPS, never roll your own crypto |
| 3 | Injection | Use ORMs, validate input with Zod/Valibot |
| 4 | Insecure Design | Rate limiting, defense in depth, separate APIs |
| 5 | Security Misconfiguration | Environment variables, hide errors in production, use helmet |
| 6 | Vulnerable Components | Regular audits, lock file dependencies, minimal packages |
| 7 | Auth Failures | Short-lived tokens, refresh tokens, account lockout |
| 8 | Integrity Failures | Signed commits, verify webhooks, integrity hashes |
| 9 | Logging Failures | Log security events, never log secrets, set up alerts |
| 10 | SSRF | Allowlist domains, block private IPs, validate protocols |

## Reference

**OWASP Top 10:2025**  
[https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)

The OWASP Top 10 is a simple list of the biggest security risks for web apps. It's created by security experts from around the world.

## 1. Broken Access Control

**What's the problem?**  
Users getting access to data or actions they shouldn't be able to see or do.

**How to fix it:**

- Check permissions on the server only (never trust what the client sends)
- Verify access at every step
- Don't trust user roles sent from the browser

**What to do:**

- Use role-based access control (like admin, user, guest)
- Make sure users can only access their own data (check if `userId === resource.ownerId`)
- Keep all permission checks in one place so you don't repeat code

```javascript
// Example 1: Check if user has permission
if (!user.hasPermission("task:update")) {
  throw new ForbiddenError();
}

// Example 2: Make sure user owns the resource
async function updateTask(taskId, userId, updates) {
  const task = await db.query.tasks.findFirst({
    where: eq(tasks.id, taskId)
  });
  
  if (!task) {
    throw new NotFoundError("Task not found");
  }
  
  // Check if this user owns the task
  if (task.ownerId !== userId) {
    throw new ForbiddenError("You don't own this task");
  }
  
  return await db.update(tasks)
    .set(updates)
    .where(eq(tasks.id, taskId));
}

// Example 3: Middleware to check user role
const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.user || !req.user.roles.includes(role)) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
};

// How to use it in routes
app.delete("/admin/users/:id", requireRole("admin"), deleteUser);
```

## 2. Cryptographic Failures

**What's the problem?**  
Sensitive data getting exposed because you're using weak encryption or storing things incorrectly.

**How to fix it:**

- Never save passwords as plain text
- Encrypt sensitive data when storing it and sending it
- Use well-tested encryption libraries only

**What to do:**

- Use bcrypt or argon2 to hash passwords
- Always use HTTPS for your website
- Don't try to create your own encryption methods

```javascript
// Example 1: Hash a password with Bun
await Bun.password.hash(password, {
  algorithm: "bcrypt",
  cost: 12,
});

// Example 2: Check if password is correct
const isValid = await Bun.password.verify(inputPassword, hashedPassword);

// Example 3: Using argon2 (for Node.js/Deno)
import argon2 from "argon2";

const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 3,
  parallelism: 1
});

// Example 4: Encrypt sensitive data before saving
import crypto from "crypto";

function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex")
  };
}

// Example 5: Set secure headers to protect your site
app.use((req, res, next) => {
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});
```

## 3. Injection (SQL, NoSQL, Command Injection)

**What's the problem?**  
User input being treated as code and running commands you didn't intend.

**How to fix it:**

- Use prepared statements for all database queries
- Never combine user input directly into queries
- Check and clean all user inputs

**What to do:**

- Use an ORM or query builder (like Drizzle, Prisma, or Kysely)
- Validate data with schema validators (Zod or Valibot)

```javascript
// Example 1: Safe database query with Drizzle
db.select()
  .from(users)
  .where(eq(users.id, userId));

// Example 2: Check user input with Zod
import { z } from "zod";

const userSchema = z.object({
  email: z.string().email(),
  age: z.number().int().min(18).max(120),
  username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_]+$/)
});

const result = userSchema.safeParse(req.body);
if (!result.success) {
  return res.status(400).json({ errors: result.error.errors });
}

// Example 3: WRONG WAY - SQL Injection (NEVER do this!)
// const query = `SELECT * FROM users WHERE email = '${email}'`; // ❌ DANGEROUS

// Example 4: RIGHT WAY - Use Prisma with safe queries
const user = await prisma.user.findUnique({
  where: { email: userEmail }
});

// Example 5: Prevent NoSQL injection
// WRONG WAY
// db.collection.find({ username: req.body.username }); // ❌ Can be hacked

// RIGHT WAY - Clean the input first
const sanitizedUsername = String(req.body.username);
db.collection.find({ username: sanitizedUsername });

// Example 6: Prevent command injection
import { exec } from "child_process";

// WRONG WAY
// exec(`ping ${userInput}`); // ❌ DANGEROUS

// RIGHT WAY - Use safe methods
import { spawn } from "child_process";
const child = spawn("ping", ["-c", "4", validatedHost]);
```

## 4. Insecure Design

**What's the problem?**  
Security holes caused by not thinking about security when building your app.

**How to fix it:**

- Think about security before you start coding
- Assume things will break and users might try to hack you

**What to do:**

- Add multiple layers of security
- Limit how many requests users can make (rate limiting)
- Keep public and internal APIs separate

```javascript
// Example 1: Stop people from spamming login attempts
import rateLimit from "express-rate-limit";

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 tries per 15 minutes
  message: "Too many login attempts, please try again later"
});

app.post("/api/login", loginLimiter, loginHandler);

// Example 2: Set request timeout
app.use((req, res, next) => {
  req.setTimeout(30000); // 30 seconds max
  res.setTimeout(30000);
  next();
});

// Example 3: Separate public and private APIs
// Public API - anyone can access
app.use("/api/public", publicRouter);

// Internal API - only for internal network
app.use("/api/internal", requireInternalNetwork, internalRouter);

// Example 4: Multiple security checks (defense in depth)
async function transferFunds(fromAccount, toAccount, amount) {
  // Check 1: Is the amount valid?
  if (amount <= 0) throw new Error("Invalid amount");
  
  // Check 2: Does the account have enough money?
  const balance = await getAccountBalance(fromAccount);
  if (balance < amount) throw new Error("Insufficient funds");
  
  // Check 3: Does this user own the account?
  if (!user.ownsAccount(fromAccount)) throw new Error("Unauthorized");
  
  // Check 4: Do the transfer safely (can rollback if something fails)
  return await db.transaction(async (tx) => {
    await tx.update(accounts)
      .set({ balance: balance - amount })
      .where(eq(accounts.id, fromAccount));
    
    await tx.update(accounts)
      .set({ balance: sql`${accounts.balance} + ${amount}` })
      .where(eq(accounts.id, toAccount));
  });
}
```

## 5. Security Misconfiguration

**What's the problem?**  
Using default settings, showing error details to users, or having features enabled that shouldn't be.

**How to fix it:**

- Set up proper configuration for each environment (dev, production)
- Turn off debug mode in production

**What to do:**

- Use environment variables (.env files)
- Don't show error stack traces to users
- Set proper HTTP security headers

```javascript
// Example 1: Different settings for production
if (process.env.NODE_ENV === "production") {
  app.disableDebug();
}

// Example 2: Hide error details from users
app.use((err, req, res, next) => {
  // Save full error for yourself
  logger.error(err.stack);
  
  // Show simple message to users
  if (process.env.NODE_ENV === "production") {
    res.status(500).json({ error: "Internal server error" });
  } else {
    res.status(500).json({ 
      error: err.message,
      stack: err.stack 
    });
  }
});

// Example 3: Add security headers with helmet
import helmet from "helmet";

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Example 4: Check your environment variables
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  PORT: z.string().transform(Number).pipe(z.number().int().positive())
});

const env = envSchema.parse(process.env);

// Example 5: Turn off features you don't need
app.disable("x-powered-by"); // Don't tell people you're using Express
app.set("trust proxy", 1); // Trust first proxy

// Example 6: Control who can access your site
import cors from "cors";

const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(",") || ["https://yourdomain.com"],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
```

## 6. Vulnerable and Outdated Components

**What's the problem?**  
Using old libraries that have known security bugs.

**How to fix it:**

- Use as few dependencies as possible
- Check for updates and security issues regularly

**What to do:**

- Run security checks on your packages
- Don't use libraries that aren't being maintained anymore
- Use lock files to keep track of exact versions (bun.lockb, package-lock.json)

```javascript
// Example 1: Check for security issues
// For npm
// $ npm audit
// $ npm audit fix

// For Bun
// $ bun audit

// For Yarn
// $ yarn audit

// Example 2: Lock your package versions in package.json
{
  "dependencies": {
    "express": "4.18.2",        // Exact version
    "helmet": "^7.1.0",         // Allow small updates
    "zod": "~3.22.4"            // Only bug fixes
  },
  "devDependencies": {
    "typescript": "5.3.3"
  }
}

// Example 3: Auto-check for updates with GitHub Actions
// .github/workflows/dependency-check.yml
/*
name: Dependency Check
on:
  schedule:
    - cron: '0 0 * * 1'  # Every Monday
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm audit
      - run: npm outdated
*/

// Example 4: Check for vulnerabilities in your code
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

async function checkDependencies() {
  try {
    const { stdout } = await execAsync("npm audit --json");
    const auditReport = JSON.parse(stdout);
    
    if (auditReport.metadata.vulnerabilities.total > 0) {
      console.error("Vulnerabilities found!", auditReport.metadata.vulnerabilities);
      process.exit(1);
    }
  } catch (error) {
    console.error("Audit failed:", error);
    process.exit(1);
  }
}

// Example 5: Use Snyk to monitor continuously
// Install: npm install -g snyk
// Commands:
// $ snyk test                    # Check for vulnerabilities
// $ snyk monitor                 # Keep monitoring
// $ snyk protect                 // Fix issues
```

## 7. Identification and Authentication Failures

**What's the problem?**  
Weak login systems that let hackers take over accounts.

**How to fix it:**

- Use strong authentication methods
- Manage login tokens properly

**What to do:**

- Make access tokens expire quickly (short-lived)
- Use separate refresh tokens
- Delete tokens when users log out
- Block repeated failed login attempts

```javascript
// Example 1: Create tokens that expire
import jwt from "jsonwebtoken";

function generateTokens(userId) {
  const accessToken = jwt.sign(
    { userId, type: "access" },
    process.env.JWT_SECRET,
    { expiresIn: "15m" } // Expires in 15 minutes
  );
  
  const refreshToken = jwt.sign(
    { userId, type: "refresh" },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" } // Expires in 7 days
  );
  
  return { accessToken, refreshToken };
}

// Example 2: Check if token is valid
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
};

// Example 3: Refresh expired tokens
async function refreshAccessToken(refreshToken) {
  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Check if refresh token was cancelled
    const isRevoked = await redis.get(`revoked:${refreshToken}`);
    if (isRevoked) {
      throw new Error("Token has been revoked");
    }
    
    // Make new tokens
    const tokens = generateTokens(decoded.userId);
    
    // Cancel old refresh token (optional but more secure)
    await redis.set(`revoked:${refreshToken}`, "1", "EX", 60 * 60 * 24 * 7);
    
    return tokens;
  } catch (error) {
    throw new Error("Invalid refresh token");
  }
}

// Example 4: Delete tokens when user logs out
app.post("/api/logout", authenticateToken, async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  
  // Add token to blacklist
  await redis.set(`blacklist:${token}`, "1", "EX", 60 * 15); // 15 minutes
  
  res.json({ message: "Logged out successfully" });
});

// Example 5: Stop people from guessing passwords
const loginAttempts = new Map();

async function handleLogin(email, password) {
  const attemptKey = `login:${email}`;
  const attempts = (await redis.get(attemptKey)) || 0;
  
  // Lock account after 5 tries
  if (attempts >= 5) {
    const lockTime = await redis.ttl(attemptKey);
    throw new Error(`Account locked. Try again in ${lockTime} seconds`);
  }
  
  const user = await db.query.users.findFirst({
    where: eq(users.email, email)
  });
  
  if (!user || !(await Bun.password.verify(password, user.passwordHash))) {
    // Count failed attempt
    await redis.incr(attemptKey);
    await redis.expire(attemptKey, 900); // Lock for 15 minutes
    throw new Error("Invalid credentials");
  }
  
  // Reset counter on successful login
  await redis.del(attemptKey);
  
  return generateTokens(user.id);
}

// Example 6: Two-factor authentication (2FA)
import speakeasy from "speakeasy";

// Create 2FA secret
function generateMFASecret(email) {
  return speakeasy.generateSecret({
    name: `YourApp (${email})`,
    length: 32
  });
}

// Check 2FA code
function verifyMFAToken(secret, token) {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: "base32",
    token: token,
    window: 2 // Allow small time difference
  });
}
```

## 8. Software and Data Integrity Failures

**What's the problem?**  
Someone changing your code or data without permission.

**How to fix it:**

- Make sure deployed code hasn't been tampered with
- Secure your deployment pipeline

**What to do:**

- Sign your builds
- Control who can deploy to production
- Keep different environments separated

```javascript
// Example 1: Make sure packages are safe
// package.json with security hashes
{
  "dependencies": {
    "express": "4.18.2"
  },
  "packageManager": "npm@9.6.7",
  "engines": {
    "node": ">=18.0.0"
  }
}

// Use lock files to ensure nothing changes
// npm: package-lock.json
// yarn: yarn.lock
// bun: bun.lockb

// Example 2: Check external scripts are safe (for HTML)
// In HTML files
/*
<script 
  src="https://cdn.example.com/library.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/ux..."
  crossorigin="anonymous">
</script>
*/

// Example 3: Verify code before deploying
// .github/workflows/deploy.yml
/*
name: Deploy with Verification
jobs:
  deploy:
    steps:
      - name: Check if commit is signed
        run: |
          git verify-commit HEAD || exit 1
      
      - name: Install packages
        run: npm ci --ignore-scripts
      
      - name: Check for security issues
        run: npm audit --audit-level=high
*/

// Example 4: Only allow deployment from certain IPs
const ALLOWED_DEPLOY_IPS = process.env.ALLOWED_DEPLOY_IPS?.split(",") || [];

app.post("/api/deploy", (req, res, next) => {
  const clientIP = req.ip;
  
  if (!ALLOWED_DEPLOY_IPS.includes(clientIP)) {
    return res.status(403).json({ 
      error: "Deployment not allowed from this IP" 
    });
  }
  
  next();
}, deployHandler);

// Example 5: Make sure deployed code hasn't been changed
async function verifyDeployment(buildHash) {
  const expectedHash = await getExpectedBuildHash();
  const actualHash = await calculateCurrentBuildHash();
  
  if (expectedHash !== actualHash) {
    throw new Error("Build integrity check failed");
  }
  
  return true;
}

// Example 6: Check database migrations haven't been tampered with
import { createHash } from "crypto";

const migrations = [
  { id: "001", hash: "abc123...", sql: "CREATE TABLE users..." },
  { id: "002", hash: "def456...", sql: "ALTER TABLE users..." }
];

async function runMigrations() {
  for (const migration of migrations) {
    const computedHash = createHash("sha256")
      .update(migration.sql)
      .digest("hex");
    
    if (computedHash !== migration.hash) {
      throw new Error(`Migration ${migration.id} integrity check failed`);
    }
    
    await db.execute(migration.sql);
  }
}

// Example 7: Verify webhook signatures
import crypto from "crypto";

function verifyWebhookSignature(payload, signature, secret) {
  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(JSON.stringify(payload))
    .digest("hex");
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

app.post("/api/webhook", (req, res) => {
  const signature = req.headers["x-signature"];
  
  if (!verifyWebhookSignature(req.body, signature, process.env.WEBHOOK_SECRET)) {
    return res.status(401).json({ error: "Invalid signature" });
  }
  
  // Process webhook
  res.json({ received: true });
});
```

## 9. Security Logging and Monitoring Failures

**What's the problem?**  
Not noticing when someone is attacking your system.

**How to fix it:**

- Record important security events
- Watch for suspicious activity

**What to do:**

- Log failed login attempts
- Track when someone tries to access things they shouldn't
- Don't save sensitive data in logs (like passwords or credit cards)

```javascript
// Example 1: Log security events
logger.warn("Failed login attempt", { userId, ip });

// Example 2: Better logging with Winston
import winston from "winston";

const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  defaultMeta: { service: "user-service" },
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

// Log security events
logger.warn("authentication_failed", {
  userId: req.body.email,
  ip: req.ip,
  userAgent: req.headers["user-agent"],
  timestamp: new Date().toISOString()
});

// Example 3: Log all requests automatically
app.use((req, res, next) => {
  const startTime = Date.now();
  
  res.on("finish", () => {
    const duration = Date.now() - startTime;
    
    const logData = {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      userId: req.user?.id
    };
    
    // Log suspicious activity
    if (res.statusCode === 401 || res.statusCode === 403) {
      logger.warn("access_denied", logData);
    }
    
    // Log all requests
    logger.info("request", logData);
  });
  
  next();
});

// Example 4: Don't log sensitive data
// WRONG WAY - Logs password
logger.info("User login", { email, password }); // ❌ NEVER DO THIS

// RIGHT WAY - Remove sensitive data
const sanitizedData = {
  email,
  // Don't log password, tokens, credit cards, etc.
};
logger.info("User login", sanitizedData);

// Example 5: Watch for suspicious patterns
async function monitorSecurityEvents() {
  const suspiciousEvents = await db
    .select()
    .from(securityLogs)
    .where(
      and(
        eq(securityLogs.eventType, "failed_login"),
        gte(securityLogs.timestamp, new Date(Date.now() - 3600000)) // Last hour
      )
    )
    .groupBy(securityLogs.ipAddress)
    .having(sql`COUNT(*) > 10`);
  
  if (suspiciousEvents.length > 0) {
    await alertSecurityTeam("Multiple failed login attempts detected", {
      events: suspiciousEvents
    });
  }
}

// Example 6: Track important actions
async function auditSensitiveOperation(userId, action, resource) {
  await db.insert(auditLogs).values({
    userId,
    action,
    resource,
    timestamp: new Date(),
    ipAddress: req.ip,
    success: true
  });
}

// How to use it
app.delete("/api/users/:id", authenticateToken, async (req, res) => {
  const targetUserId = req.params.id;
  
  await auditSensitiveOperation(
    req.user.id,
    "DELETE_USER",
    `user:${targetUserId}`
  );
  
  await deleteUser(targetUserId);
  res.json({ success: true });
});

// Example 7: Send alerts for critical events
import { sendAlert } from "./alerting";

async function logCriticalEvent(event, details) {
  logger.error(event, details);
  
  // Send immediate alert for serious problems
  if (["data_breach", "privilege_escalation", "mass_deletion"].includes(event)) {
    await sendAlert({
      severity: "critical",
      event,
      details,
      timestamp: new Date()
    });
  }
}

// Example 8: Rotate log files automatically
// Using winston-daily-rotate-file
import DailyRotateFile from "winston-daily-rotate-file";

const transport = new DailyRotateFile({
  filename: "application-%DATE%.log",
  datePattern: "YYYY-MM-DD",
  maxSize: "20m",
  maxFiles: "14d", // Keep for 14 days
  compress: true
});

logger.add(transport);
```

## 10. Server-Side Request Forgery (SSRF)

**What's the problem?**  
Hackers tricking your server into making requests to places it shouldn't.

**How to fix it:**

- Check all URLs before your server visits them
- Block access to internal networks

**What to do:**

- Only allow specific trusted domains
- Block private IP addresses
- Turn off network features you don't need

```javascript
// Example 1: Only allow safe URLs
const ALLOWED_DOMAINS = [
  "api.example.com",
  "cdn.example.com",
  "trusted-partner.com"
];

function isAllowedURL(url) {
  try {
    const parsed = new URL(url);
    return ALLOWED_DOMAINS.includes(parsed.hostname);
  } catch {
    return false;
  }
}

app.post("/api/fetch", async (req, res) => {
  const { url } = req.body;
  
  if (!isAllowedURL(url)) {
    return res.status(400).json({ error: "URL not allowed" });
  }
  
  const response = await fetch(url);
  const data = await response.json();
  res.json(data);
});

// Example 2: Block private IPs
function isPrivateIP(hostname) {
  const privateRanges = [
    /^127\./,                    // Localhost
    /^10\./,                     // Private network
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private network
    /^192\.168\./,               // Private network
    /^169\.254\./,               // Link-local
    /^localhost$/i,
    /^0\.0\.0\.0$/,
    /^\:\:1$/,                   // IPv6 localhost
    /^fc00\:/,                   // IPv6 private
    /^fe80\:/                    // IPv6 link-local
  ];
  
  return privateRanges.some(range => range.test(hostname));
}

async function validateAndFetch(url) {
  const parsed = new URL(url);
  
  // Check for private IPs
  if (isPrivateIP(parsed.hostname)) {
    throw new Error("Access to private IPs is blocked");
  }
  
  // Resolve hostname to IP
  const dns = require("dns").promises;
  const addresses = await dns.resolve4(parsed.hostname);
  
  // Check if any resolved IP is private
  if (addresses.some(isPrivateIP)) {
    throw new Error("Hostname resolves to private IP");
  }
  
  return await fetch(url);
}

// Example 3: Only allow HTTPS
function validateProtocol(url) {
  const parsed = new URL(url);
  
  // Only allow HTTPS
  if (parsed.protocol !== "https:") {
    throw new Error("Only HTTPS URLs are allowed");
  }
  
  return true;
}

// Example 4: Complete SSRF protection
import { isIP } from "net";

async function safeFetch(url, options = {}) {
  // Check if URL is valid
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid URL");
  }
  
  // Check protocol
  if (!["https:", "http:"].includes(parsed.protocol)) {
    throw new Error("Invalid protocol");
  }
  
  // Check if domain is allowed
  if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
    throw new Error("Domain not in allowlist");
  }
  
  // Don't allow direct IP access
  if (isIP(parsed.hostname)) {
    throw new Error("Direct IP access not allowed");
  }
  
  // Check DNS resolution
  const dns = require("dns").promises;
  try {
    const addresses = await dns.resolve4(parsed.hostname);
    
    for (const addr of addresses) {
      if (isPrivateIP(addr)) {
        throw new Error("Hostname resolves to private IP");
      }
    }
  } catch (error) {
    throw new Error("DNS resolution failed");
  }
  
  // Add timeout to prevent hanging
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    
    return response;
  } finally {
    clearTimeout(timeout);
  }
}

// Example 5: Validate webhook callbacks
app.post("/api/webhook/callback", async (req, res) => {
  const { callbackUrl } = req.body;
  
  // Check callback URL before making request
  if (!isAllowedURL(callbackUrl)) {
    return res.status(400).json({ error: "Invalid callback URL" });
  }
  
  try {
    await safeFetch(callbackUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "completed" })
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Example 6: Fetch images safely
async function fetchImage(imageUrl) {
  // Validate URL
  await validateAndFetch(imageUrl);
  
  // Fetch with size limit
  const response = await fetch(imageUrl);
  
  // Check if it's actually an image
  const contentType = response.headers.get("content-type");
  if (!contentType?.startsWith("image/")) {
    throw new Error("URL does not point to an image");
  }
  
  // Check file size (5MB max)
  const contentLength = response.headers.get("content-length");
  if (contentLength && parseInt(contentLength) > 5 * 1024 * 1024) {
    throw new Error("Image too large");
  }
  
  return response;
}
```

## Why Bun?

These security tips work with Node.js and Deno too, but Bun has some nice features:

- Password hashing built right in
- Starts up and runs faster
- Modern tools with good security by default

But remember: security depends on how you build your app, not which tool you use. A badly built Bun app is just as vulnerable as a badly built Node.js app.

## Final Thoughts

Security isn't something you add at the end — it's something you do all the time.

When you follow the OWASP Top 10 guidelines, check user inputs, control who can access what, and secure your login system, you make your app much harder to hack.

Whether you're using Bun, Node.js, or Deno, your job stays the same:

**Build it secure. Set it up secure. Keep it secure.**

## Next Steps

1. **Audit your current project** - Run `npm audit` or `bun audit` today
2. **Add input validation** - Pick Zod or Valibot and validate all user inputs
3. **Review authentication** - Check your token expiration and refresh logic
4. **Set up logging** - Start with Winston and log security events
5. **Schedule regular reviews** - Security is ongoing, not a one-time task


## Resources

- [OWASP Top 10:2025](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Snyk Vulnerability Database](https://snyk.io/vuln/)