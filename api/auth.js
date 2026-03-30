const crypto = require('crypto');

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({});

  let body = {};
  try { body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {}); } catch {}

  await new Promise(r => setTimeout(r, 280 + Math.floor(Math.random() * 180)));

  const pw = String(body.pw || '');
  const P = process.env.APP_PW || '';
  const S = process.env.JWT_SECRET || '';

  if (!P || !S) return res.status(500).json({ e: 'server_config' });
  if (!pw || pw.length > 128) return res.status(400).json({ e: 'invalid_input' });

  const ok = crypto.timingSafeEqual(
    Buffer.from(pw.padEnd(128)),
    Buffer.from(P.padEnd(128))
  ) && pw === P;

  if (!ok) return res.status(401).json({ e: 'invalid_password' });

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 21600;
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify({ iat, exp })).toString('base64url');
  const s = crypto.createHmac('sha256', S).update(`${h}.${p}`).digest('base64url');

  res.json({ t: `${h}.${p}.${s}` });
};
