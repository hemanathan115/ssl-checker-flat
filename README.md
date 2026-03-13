# 🔐 SSL Certificate Checker

A web tool to instantly inspect SSL/TLS certificates for any website.

## Files in this folder

| File | Description |
|------|-------------|
| `server.js` | Express + Node.js backend (SSL checker API) |
| `package.json` | Node.js dependencies |
| `public/index.html` | Frontend (HTML + CSS + JS all-in-one) |
| `README.md` | This file |

## How to Run

```bash
npm install
npm start
```

Then open: **http://localhost:3001**

## Features

- Certificate Issuer (Organization, CN, Country)
- Validity Period (issued, expiry, days left)
- Encryption (TLS version, cipher suite)
- Security Score (0–100)
- Expiry warnings
- Subject Alt Names

## API

```
GET /api/check?url=example.com
```

---
Author: hemanathan115 · SSL Inspector v1.0
