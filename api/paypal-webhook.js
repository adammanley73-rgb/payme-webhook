// /api/paypal-webhook.js
import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  try {
    // Required PayPal headers
    const h = req.headers;
    const transmissionId   = h['paypal-transmission-id'];
    const transmissionTime = h['paypal-transmission-time'];
    const certUrl          = h['paypal-cert-url'];
    const authAlgo         = h['paypal-auth-algo'];
    const transmissionSig  = h['paypal-transmission-sig'];

    if (!transmissionId || !transmissionTime || !certUrl || !authAlgo || !transmissionSig) {
      return res.status(400).json({ ok:false, error:'Missing PayPal signature headers' });
    }

    // Parse body (supports raw or pre-parsed)
    const body = await readBody(req);
    const evtType = body?.event_type;

    // OAuth to PayPal (Sandbox or Live based on PAYPAL_BASE)
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
      return res.status(400).json({ ok:false, error:'OAuth failed' });
    }

    // Verify webhook signature
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
        webhook_event:    body
      })
    });
    const verifyData = await verifyResp.json();

    if (!verifyResp.ok || verifyData.verification_status !== 'SUCCESS') {
      // Return 400 so PayPal may retry (keeps failures visible)
      return res.status(400).json({ ok:false, error:'Invalid signature' });
    }

    // Idempotency guard (PayPal may retry)
    try {
      const evtId = body?.id;
      if (evtId) {
        const seen = await kv.get(`pp:${evtId}`);
        if (seen) return res.status(200).json({ ok: true, deduped: true });
        await kv.set(`pp:${evtId}`, 1, { ex: 60 * 60 * 24 * 14 }); // 14 days
      }
    } catch {
      // do not fail webhook for transient KV issues
    }

    // Minimal router
    switch (evtType) {
      case 'PAYMENT.CAPTURE.COMPLETED': {
        const cap = body?.resource;
        const captureId = cap?.id;
        const amount = cap?.amount?.value;
        const currency = cap?.amount?.currency_code;
        const orderRef = cap?.custom_id || cap?.invoice_id || `Payment completed for ${amount} ${currency}`;
        await markOrderPaid({ captureId, amount, currency, orderRef, raw: body });
        break;
      }

      case 'PAYMENT.CAPTURE.REFUNDED': {
        const refund = body?.resource;
        const refundId = refund?.id;
        const captureId = refund?.sale_id || refund?.capture_id;
        const amount = refund?.amount?.value;
        const currency = refund?.amount?.currency_code;
        await markRefund({ refundId, captureId, amount, currency, raw: body });
        break;
      }

      case 'BILLING.SUBSCRIPTION.CANCELLED': {
        const sub = body?.resource;
        const subscriptionId = sub?.id;
        await endSubscription({ subscriptionId, raw: body });
        break;
      }

      default:
        // Return 200 even for unhandled types so PayPal stops retrying
        break;
    }

    // Always 200 after verified & processed
    return res.status(200).json({ ok: true });
  } catch (err) {
    // In production keep this minimal; PayPal will retry on 500s
    return res.status(500).json({ ok:false, error:'Server error' });
  }
}

async function readBody(req) {
  if (typeof req.body === 'object' && req.body) return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { return {}; } }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return {}; }
}

// —— Your app hooks (replace with real implementations) ——
async function markOrderPaid({ captureId, amount, currency, orderRef, raw }) {
  // TODO: update your order in DB, fulfill, email, etc.
  console.log('Paid:', { captureId, amount, currency, orderRef });
}
async function markRefund({ refundId, captureId, amount, currency, raw }) {
  // TODO: update order/refund records
  console.log('Refunded:', { refundId, captureId, amount, currency });
}
async function endSubscription({ subscriptionId, raw }) {
  // TODO: mark subscription ended
  console.log('Subscription cancelled:', { subscriptionId });
}
