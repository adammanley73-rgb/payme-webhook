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
    const bodyObj = typeof req.body === 'object' && req.body ? req.body : (await readJsonBody(req));

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
      return res.status(400).json({ ok:false, error:'OAuth failed', details: tokenData });
    }

    // 2) Verify webhook signature
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

    // 3) Idempotency guard
    try {
      const evtId = bodyObj?.id;
      if (evtId) {
        const seen = await kv.get(`pp:${evtId}`);
        if (seen) return res.status(200).json({ ok: true, deduped: true });
        await kv.set(`pp:${evtId}`, 1, { ex: 60 * 60 * 24 * 14 }); // 14 days
      }
    } catch (e) {
      console.warn('KV guard error (continuing):', e?.message || e);
    }

    // 4) Business logic
    const type = bodyObj?.event_type;
    const r = bodyObj?.resource ?? {};
    switch (type) {
      case 'PAYMENT.CAPTURE.COMPLETED':
        await handleCaptureCompleted(r);
        console.log('Handled capture completed:', r?.id);
        break;

      case 'PAYMENT.CAPTURE.REFUNDED':
        await handleCaptureRefunded(r);
        console.log('Handled capture refunded:', r?.id);
        break;

      case 'BILLING.SUBSCRIPTION.CANCELLED':
        await handleSubscriptionCancelled(r);
        console.log('Handled subscription cancelled:', r?.id);
        break;

      default:
        // Accept but don’t act on other events
        console.log('Unhandled event type:', type);
        break;
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Webhook error', err);
    return res.status(500).json({ ok:false, error:'Server error' });
  }
}

async function handleCaptureCompleted(resource) {
  const captureId = resource?.id;
  const amount    = resource?.amount?.value;
  const currency  = resource?.amount?.currency_code;
  const orderRef  = resource?.custom_id
                 ?? resource?.invoice_id
                 ?? resource?.supplementary_data?.related_ids?.order_id
                 ?? null;

  if (!captureId) return;

  // Store a simple ledger record
  try {
    await kv.hset(`pp:cap:${captureId}`, {
      status: 'paid',
      amount,
      currency,
      orderRef,
      ts: Date.now()
    });
  } catch (e) {
    console.warn('KV write error (capture):', e?.message || e);
  }
}

async function handleCaptureRefunded(resource) {
  const refundId  = resource?.id;
  const amount    = resource?.amount?.value;
  const currency  = resource?.amount?.currency_code;

  // Try to find the capture id from links or related ids
  const captureIdFromLink = resource?.links?.find(l => l?.rel === 'up')?.href?.split('/')?.pop();
  const captureIdRelated  = resource?.supplementary_data?.related_ids?.capture_id;
  const captureId = captureIdFromLink || captureIdRelated || null;

  if (!refundId) return;

  try {
    await kv.hset(`pp:refund:${refundId}`, {
      status: 'refunded',
      amount,
      currency,
      captureId,
      ts: Date.now()
    });
    if (captureId) {
      await kv.hset(`pp:cap:${captureId}`, { refunded: 'yes', refundId });
    }
  } catch (e) {
    console.warn('KV write error (refund):', e?.message || e);
  }
}

async function handleSubscriptionCancelled(resource) {
  const subId = resource?.id;
  if (!subId) return;

  try {
    await kv.hset(`pp:sub:${subId}`, {
      status: 'cancelled',
      ts: Date.now()
    });
  } catch (e) {
    console.warn('KV write error (sub cancel):', e?.message || e);
  }
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  try { return JSON.parse(raw); } catch { return {}; }
}
