// /api/paypal-webhook.js
import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  try {
    // 0) Required PayPal headers
    const h = req.headers;
    const transmissionId   = h['paypal-transmission-id'];
    const transmissionTime = h['paypal-transmission-time'];
    const certUrl          = h['paypal-cert-url'];
    const authAlgo         = h['paypal-auth-algo'];
    const transmissionSig  = h['paypal-transmission-sig'];

    if (!transmissionId || !transmissionTime || !certUrl || !authAlgo || !transmissionSig) {
      console.log('Missing PayPal headers', { transmissionId, transmissionTime, certUrl, authAlgo, transmissionSig });
      return res.status(400).json({ ok:false, error:'Missing PayPal signature headers' });
    }

    // Read JSON body (supports both parsed and raw)
    const bodyObj = typeof req.body === 'object' && req.body
      ? req.body
      : (await readJsonBody(req));

    // 1) OAuth (Bearer token)
    const tokenResp = await fetch(`${process.env.PAYPAL_BASE}/v1/oauth2/token`, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer
          .from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`)
          .toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: 'grant_type=client_credentials'
    });
    const tokenData = await tokenResp.json();
    if (!tokenResp.ok) {
      console.log('OAuth error', tokenResp.status, tokenData);
