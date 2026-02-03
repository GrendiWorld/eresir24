# ?? Security Features

## Implemented Security Measures

### 1. **DDoS Protection**
- ? Advanced rate limiting with Flask-Limiter
- ? Multi-layer rate limiting (per-endpoint + global)
- ? IP blocking for excessive requests
- ? Request counting and tracking

**Rate Limits:**
- Login: 5 attempts per minute
- Public API: 10-50 requests per minute (depending on endpoint)
- Global: 200 requests per hour, 50 per minute

### 2. **SQL Injection Protection**
- ? SQLAlchemy ORM uses parameterized queries automatically
- ? Input validation and sanitization
- ? No raw SQL queries with user input
- ? Type checking and length limits

### 3. **File Access Protection**
- ? Block access to `.py`, `.pyc`, `.pyo`, `.pyd` files
- ? Block access to `.db`, `.sqlite`, `.sql` files
- ? Block access to config files (`.env`, `.ini`, `.conf`, `.yaml`)
- ? Block access to hidden files
- ? Block path traversal attempts (`..`, `//`)
- ? Block access to `/instance/` directory

### 4. **Brute Force Protection**
- ? Login attempt tracking per IP
- ? Automatic IP blocking after 5 failed attempts
- ? 15-minute cooldown period
- ? Security logging

### 5. **Input Validation**
- ? Config name validation (alphanumeric, dash, underscore only)
- ? Length limits on all inputs
- ? Reserved name blocking
- ? Dangerous pattern detection

### 6. **Security Headers**
- ? Content-Security-Policy
- ? Strict-Transport-Security (HSTS)
- ? X-Content-Type-Options: nosniff
- ? Referrer-Policy
- ? Feature-Policy

## Security Best Practices

1. **Never run in debug mode in production** ?
2. **Use strong SECRET_KEY** ? (auto-generated if not set)
3. **Validate all user input** ?
4. **Use parameterized queries** ? (SQLAlchemy)
5. **Limit request sizes** ?
6. **Implement rate limiting** ?
7. **Block sensitive files** ?
8. **Log security events** ?

## Additional Recommendations

1. **Set SECRET_KEY environment variable** in production
2. **Enable HTTPS** and set `force_https=True` in Talisman config
3. **Use a reverse proxy** (nginx) for additional protection
4. **Regular security audits** of logs
5. **Keep dependencies updated**
