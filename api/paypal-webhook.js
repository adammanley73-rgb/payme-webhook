// Safer PayPal webhook for Vercel (lazy email import + robust body parse)
export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  const headers = Object.fromEntries(
    Object.entries(req.headers || {}).map(([k, v]) => [k.toLowerCase(), v])
  );

  let body = req.body;
  if (!body || typeof body !== "object") {
    try {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const raw = Buffer.concat(chunks).toString("utf8");
      body = raw ? JSON.parse(raw) : {};
    } catch {
      body = {};
    }
  }

  const tokenResp = await fetch(`${process.env.PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization:
        "Basic " +
        Buffer.from(
          `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`
        ).toString("base64"),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  const { access_token } = await tokenResp.json();

  const verifyResp = await fetch(
    `${process.env.PAYPAL_BASE}/v1/notifications/verify-webhook-signature`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        transmission_id: headers["paypal-transmission-id"],
        transmission_time: headers["paypal-transmission-time"],
        transmission_sig: headers["paypal-transmission-sig"],
        cert_url: headers["paypal-cert-url"],
        auth_algo: headers["paypal-auth-algo"],
        webhook_id: process.env.PAYPAL_WEBHOOK_ID,
        webhook_event: body,
      }),
    }
  );
  const verify = await verifyResp.json();
  if (verify.verification_status !== "SUCCESS") {
    return res.status(400).json({ ok: false, reason: "bad signature" });
  }

  const event = body?.event_type;
  const resource = body?.resource || {};
  const buyerEmail =
    resource?.payer?.email_address ||
    resource?.subscriber?.email_address ||
    resource?.payment_source?.paypal?.email_address ||
    "unknown";

  if (event === "PAYMENT.CAPTURE.COMPLETED" || event === "PAYMENT.SALE.COMPLETED") {
    await sendEmail(
      buyerEmail,
      "Your PAY-ME access",
      [
        "Thanks for your payment. Your PAY-ME license is active.",
        "Sign in: https://YOUR-APP-DOMAIN/login",
        "Help: thebusinessconsortium@outlook.com",
      ].join("\n")
    );
  }

  if (event === "PAYMENT.CAPTURE.REFUNDED" || event === "BILLING.SUBSCRIPTION.CANCELLED") {
    await sendEmail(
      buyerEmail,
      "PAY-ME access updated",
      "Your PAY-ME license is no longer active. Contact support if this is unexpected."
    );
  }

  return res.json({ ok: true });
}

async function sendEmail(to, subject, text) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return;
  const { default: nodemailer } = await import("nodemailer");
  const transporter = nodemailer.createTransport({
    host: "smtp.office365.com",
    port: 587,
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  await transporter.sendMail({
    from: `"The Business Consortium Ltd" <${process.env.SMTP_USER}>`,
    to,
    subject,
    text,
  });
}
