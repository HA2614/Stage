const crypto = require('crypto');

function vt(token, secret) {
  try {
    const pts = token.split('.');
    if (pts.length !== 3) return null;
    const [h, b, s] = pts;
    const exp = crypto.createHmac('sha256', secret).update(`${h}.${b}`).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(s), Buffer.from(exp))) return null;
    return JSON.parse(Buffer.from(b, 'base64url').toString('utf8'));
  } catch { return null; }
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') return res.status(405).json({});
  const auth = req.headers['authorization'] || '';
  const tok = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const S = process.env.JWT_SECRET || '';
  if (!tok || !S) return res.status(401).json({ ok: false });
  const payload = vt(tok, S);
  if (!payload || payload.exp < Math.floor(Date.now() / 1000)) return res.status(401).json({ ok: false });
  res.json({ ok: true });
};
