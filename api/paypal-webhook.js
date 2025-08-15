// /api/paypal-webhook.js
import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  try {
    // --- 0) Required PayPal headers ---
    const h = req.headers;
    const transmissionId   = h['paypal-transmission-id'];
    const transmissionTime = h['paypal-transmission-time'];
    const certUrl          = h['paypal-cert-url'];
    const authAlgo         = h['paypal-auth-algo'];
    const transmissionSig  = h['paypal-transmission-sig'];

    if (!transmissionId || !transmissionTime || !certUrl || !authAlgo || !transmissionSig) {
      return res.status(400).json({ ok:false, error:'Missing PayPal signature headers' });
    }

    // Support both parsed and raw JSON
    const bodyObj = (typeof req.body === 'object' && req.body) ? req.body : await readJsonBody(req);

    // --- 1) OAuth (Sandbox base must be https://api-m.sandbox.paypal.com) ---
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

    // --- 2) Verify PayPal signature ---
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

    // --- 3) Idempotency guard (dedupe by event id) ---
    try {
      const evtId = bodyObj?.id; // PayPal event id, like WH-XXXX
      if (evtId) {
        const seen = await kv.get(`pp:${evtId}`);
        if (seen) {
          return res.status(200).json({ ok: true, deduped: true });
        }
        // keep dedupe markers for 14 days
        await kv.set(`pp:${evtId}`, 1, { ex: 60 * 60 * 24 * 14 });
      }
    } catch (e) {
      console.warn('KV guard error (continuing):', e?.message || e);
    }

    // --- 4) Handle events and write business keys to KV ---
    const type = bodyObj?.event_type;
    const r    = bodyObj?.resource || {};

    if (type === 'PAYMENT.CAPTURE.COMPLETED') {
      const captureId = r.id;
      const amount    = r?.amount?.value;
      const currency  = r?.amount?.currency_code;
      const orderRef  = r?.custom_id || r?.invoice_id || bodyObj?.summary;

      const payload = {
        type,
        captureId,
        amount,
        currency,
        orderRef,
        status: r?.status,
        ts: bodyObj?.create_time,
      };

      await kv.set(`pp:cap:${captureId}`, JSON.stringify(payload), { ex: 60 * 60 * 24 * 30 }); // 30 days
      console.log(`Handled capture completed: ${captureId}`, payload);
    }
    else if (type === 'PAYMENT.CAPTURE.REFUNDED') {
      // resource.id here is the REFUND id
      const refundId  = r.id;
      const amount    = r?.amount?.value;
      const currency  = r?.amount?.currency_code;
      const note      = bodyObj?.summary;

      const payload = {
        type,
        refundId,
        amount,
        currency,
        note,
        status: r?.status,
        ts: bodyObj?.create_time,
      };

      await kv.set(`pp:refund:${refundId}`, JSON.stringify(payload), { ex: 60 * 60 * 24 * 30 });
      console.log(`Handled capture refunded: ${refundId}`, payload);
    }
    else if (type === 'BILLING.SUBSCRIPTION.CANCELLED') {
      const subId     = r.id;
      const reason    = r?.cancellation_effective_date || bodyObj?.summary;

      const payload = {
        type,
        subscriptionId: subId,
        reason,
        ts: bodyObj?.create_time,
      };

      await kv.set(`pp:sub:${subId}`, JSON.stringify(payload), { ex: 60 * 60 * 24 * 30 });
      console.log(`Handled subscription cancelled: ${subId}`, payload);
    } else {
      // Verified but unhandled — still acknowledge so PayPal stops retrying
      console.log('Verified, unhandled event:', type);
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
