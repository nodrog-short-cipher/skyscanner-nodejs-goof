# Security Audit Report

**Repository:** skyscanner-nodejs-goof
**Date:** 2026-01-31
**Auditor:** Automated Security Audit

## Summary

This repository is an intentionally vulnerable Node.js application (Snyk "goof" demo). It contains **14+ distinct security vulnerabilities** across application code, configuration, and dependencies. None of these issues are accidental -- they exist for educational and security testing purposes.

**This application must never be deployed to production.**

---

## Critical Vulnerabilities

### 1. Command Injection (CWE-78)

**File:** `routes/index.js:161`

User input from `req.body.content` is matched against an image URL regex and passed directly to `child_process.exec()` without sanitization.

```javascript
exec('identify ' + url, function (err, stdout, stderr) { ... });
```

**Impact:** Remote Code Execution. An attacker can execute arbitrary OS commands.
**Example payload:** `![alt text](http://x"; cat /etc/passwd; " "title")`

### 2. Hardcoded Secrets and Credentials (CWE-798)

| Secret | File | Line |
|--------|------|------|
| Session secret `'keyboard cat'` | `app.js` | 43 |
| API token `SECRET_TOKEN_f8ed84e8f41e4146403dd4a6bbcea5e418d23a9` | `app.js` | 83 |
| Admin password `'SuperSecretPassword'` | `mongoose-db.js` | 52 |
| MySQL credentials `root/root` | `typeorm-db.js` | 11-12 |

**Impact:** Session hijacking, unauthorized access, credential reuse attacks.

### 3. Vulnerable Dependencies (CWE-1035)

| Package | Version | Vulnerability |
|---------|---------|--------------|
| `adm-zip` | 0.4.7 | Zip Slip (arbitrary file write) |
| `mongoose` | 4.2.4 | Buffer memory exposure |
| `marked` | 0.3.5 | Cross-Site Scripting |
| `st` | 0.2.4 | Directory traversal |
| `ms` | 0.7.1 | Regular Expression DoS |
| `lodash` | 4.17.4 | Prototype pollution |
| `ejs` | 1.0.0 | Template injection |
| `express` | 4.12.4 | Multiple known CVEs |

---

## High Severity Vulnerabilities

### 4. Open Redirect (CWE-601)

**File:** `routes/index.js:41,61`

The `redirectPage` parameter from the login form body is used directly in `res.redirect()` without validating that it points to a same-origin URL.

```javascript
return res.redirect(redirectPage)
```

**Impact:** Phishing attacks via trusted domain redirect.

### 5. Reflected XSS (CWE-79)

**File:** `views/admin.ejs:17`

The `redirectPage` query parameter is rendered unescaped using EJS `<%- %>` syntax:

```html
<input type="hidden" name="redirectPage" value="<%- redirectPage %>" />
```

**Impact:** Arbitrary JavaScript execution in victim's browser.

### 6. Stored XSS via Markdown (CWE-79)

**File:** `views/index.ejs:20`

Todo content is rendered through `marked()` using unescaped EJS output:

```html
<%- marked(new String(todo.content)) %>
```

**Impact:** Persistent JavaScript execution for all users viewing the todo list.

### 7. Zip Slip / Path Traversal in Archive Extraction (CWE-22)

**File:** `routes/index.js:257`

Uploaded ZIP files are extracted with `zip.extractAllTo()` without validating entry paths:

```javascript
zip.extractAllTo(extracted_path, true);
```

**Impact:** Arbitrary file overwrite on the server filesystem.

### 8. Prototype Pollution (CWE-1321)

**File:** `routes/index.js:347`

User-controlled message body is merged using `lodash.merge()`:

```javascript
_.merge(message, req.body.message, { ... });
```

**Impact:** Object prototype pollution leading to property injection, potential RCE in downstream code.

### 9. Plaintext Password Storage (CWE-256)

**Files:** `mongoose-db.js:12-14`, `routes/index.js:315,39`

Passwords are stored as plain strings in MongoDB and compared directly without hashing.

**Impact:** Full credential exposure if database is compromised.

---

## Medium Severity Vulnerabilities

### 10. Directory Traversal via Static File Serving (CWE-22)

**File:** `app.js:72`

The `st` module (v0.2.4) has known directory traversal vulnerabilities.

### 11. Insecure Session Configuration (CWE-614)

**File:** `app.js:42-46`

Session cookies are missing `httpOnly`, `secure`, and `sameSite` flags.

### 12. Weak Credentials (CWE-521)

**File:** `routes/index.js:315`

Hardcoded test user with password `'pwd'`.

### 13. Error Information Disclosure (CWE-209)

**File:** `app.js:79-80`

Development error handler exposes full stack traces.

### 14. Insufficient Input Sanitization Before Rendering (CWE-79)

**File:** `routes/index.js:91-112`

Profile data is validated with `validator` but not sanitized before rendering in Handlebars template, enabling template injection.

---

## Recommendations

Since this is an intentionally vulnerable demo application, these recommendations apply if the codebase were to be hardened:

1. **Replace `exec()` with safe alternatives** -- use `execFile()` with argument arrays, or dedicated libraries for image processing
2. **Move all secrets to environment variables** -- use a secrets manager in production
3. **Update all dependencies** -- run `npm audit fix` and upgrade to current major versions
4. **Hash passwords** -- use `bcrypt` or `argon2` for password storage
5. **Validate redirects** -- restrict to same-origin or a whitelist of allowed URLs
6. **Escape template output** -- use `<%= %>` instead of `<%- %>` in EJS templates
7. **Validate ZIP entry paths** -- reject entries with `..` path components before extraction
8. **Sanitize objects before merging** -- strip `__proto__`, `constructor`, and `prototype` keys from user input
9. **Secure session cookies** -- set `httpOnly: true`, `secure: true`, `sameSite: 'strict'`
10. **Implement rate limiting and CSRF protection** on all state-changing endpoints
