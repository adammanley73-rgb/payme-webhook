// /api/paypal-webhook.js
import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  try {
    // 0) PayPal headers (Node lowercases them)
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

    // Body (works whether bodyParser ran or not)
    const bodyObj = typeof req.body === 'object' && req.body
      ? req.body
      : (await readJsonBody(req));

    // 1) OAuth
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

    // 2) Verify signature
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

    // 3) Idempotency guard (KV)
    try {
      const evtId = bodyObj?.id;
      if (evtId) {
        const seen = await kv.get(`pp:${evtId}`);
        if (seen) {
          return res.status(200).json({ ok: true, deduped: true });
        }
        await kv.set(`pp:${evtId}`, 1, { ex: 60 * 60 * 24 * 14 }); // 14 days
      }
    } catch (e) {
      console.warn('KV guard error (continuing):', e?.message || e);
    }

    // 4) Business logic
    const eventType = bodyObj?.event_type;
    const r = bodyObj?.resource || {};
    console.log('Event received:', eventType, r?.id);

    switch (eventType) {
      case 'PAYMENT.CAPTURE.COMPLETED': {
        const captureId = r.id;
        const amount    = r.amount?.value;
        const currency  = r.amount?.currency_code;
        const orderRef  = r.custom_id || r.invoice_id || bodyObj.summary || captureId;

        // TODO: mark order paid, trigger fulfilment
        console.log('Paid:', { captureId, amount, currency, orderRef });
        break;
      }

      case 'PAYMENT.CAPTURE.REFUNDED': {
        const refundId  = r.id;
        const captureId =
          r.seller_payable_breakdown?.related_ids?.capture_id ||
          r.supplementary_data?.related_ids?.capture_id;
        const amount   = r.amount?.value;
        const currency = r.amount?.currency_code;

        // TODO: mark refund in your system
        console.log('Refunded:', { refundId, captureId, amount, currency });
        break;
      }

      case 'BILLING.SUBSCRIPTION.CANCELLED': {
        const subId  = r.id;
        const reason = r.status_change_note || 'cancelled';

        // TODO: end subscription in your system
        console.log('Subscription cancelled:', { subId, reason });
        break;
      }

      default: {
        // Return 200 so PayPal stops retrying unhandled but valid events
        console.log('Unhandled event:', eventType);
      }
    }

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
