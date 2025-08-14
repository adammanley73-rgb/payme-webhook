// /api/paypal-webhook.js
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  try {
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

    const bodyObj = typeof req.body === 'object' && req.body
      ? req.body
      : (await readJsonBody(req));

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
      return res.status(400).json({ ok:false, error:'OAuth failed', details: tokenData });
    }

    const verifyResp = await fetch(`${process.env.PAYPAL_BASE}/v1/notifications/verify-webhook-signature`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        transmission_id:  transmissionId,
        transmission_time: transmissionTime,
        cert_url:         certUrl,
        auth_algo:        authAlgo,
        transmission_sig: transmissionSig,
        webhook_id:       process.env.PAYPAL_WEBHOOK_ID,
        webhook_event:    bodyObj
      })
    });
    const verifyData = await verifyResp.json();
    console.log('Verify result', verifyResp.status, verifyData);

    if (!verifyResp.ok || verifyData.verification_status !== 'SUCCESS') {
      return res.status(400).json({ ok:false, error:'Invalid signature', details: verifyData });
    }

    console.log('Event received:', bodyObj.event_type);
    return res.status(200).json({ ok: true });

  } catch (err) {
    console.error('Webhook error', err);
    return res.status(500).json({ ok:false, error:'Server error' });
  }
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  try { return JSON.parse(raw); } catch { return {}; }
}
