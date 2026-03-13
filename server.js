const express = require('express');
const https = require('https');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function checkSSL(hostname) {
  return new Promise((resolve, reject) => {
    const options = {
      host: hostname,
      port: 443,
      method: 'GET',
      rejectUnauthorized: false,
      servername: hostname,
    };

    const req = https.request(options, (res) => {
      const cert = res.socket.getPeerCertificate(true);

      if (!cert || Object.keys(cert).length === 0) {
        return reject(new Error('No certificate found'));
      }

      const now = new Date();
      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
      const isValid = now >= validFrom && now <= validTo;

      const cipher = res.socket.getCipher();

      let score = 0;
      if (isValid) score += 40;
      if (daysUntilExpiry > 30) score += 20;
      if (daysUntilExpiry > 90) score += 10;
      if (cipher && cipher.name && cipher.name.includes('TLS')) score += 15;
      if (cipher && cipher.version && cipher.version.includes('TLSv1.3')) score += 15;
      else if (cipher && cipher.version && cipher.version.includes('TLSv1.2')) score += 10;
      if (cert.subjectaltname) score += 10;

      resolve({
        hostname,
        subject: { CN: cert.subject?.CN || hostname, O: cert.subject?.O || 'Unknown', C: cert.subject?.C || 'Unknown' },
        issuer: { CN: cert.issuer?.CN || 'Unknown', O: cert.issuer?.O || 'Unknown', C: cert.issuer?.C || 'Unknown' },
        validFrom: validFrom.toISOString(),
        validTo: validTo.toISOString(),
        daysUntilExpiry,
        isValid,
        serialNumber: cert.serialNumber || 'N/A',
        fingerprint: cert.fingerprint || 'N/A',
        cipher: cipher?.name || 'Unknown',
        protocol: cipher?.version || 'Unknown',
        subjectAltNames: cert.subjectaltname ? cert.subjectaltname.split(', ').map(s => s.replace('DNS:', '')) : [],
        securityScore: Math.min(score, 100),
      });
    });

    req.on('error', (err) => reject(err));
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Connection timed out')); });
    req.end();
  });
}

app.get('/api/check', async (req, res) => {
  let { url } = req.query;
  if (!url) return res.status(400).json({ error: 'URL parameter is required' });
  url = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
  if (!url) return res.status(400).json({ error: 'Invalid URL' });
  try {
    const result = await checkSSL(url);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to check SSL certificate' });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`SSL Checker running on http://localhost:${PORT}`));
