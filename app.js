require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Resend } = require("resend");
const admin = require("firebase-admin");

admin.initializeApp({
  credential: admin.credential.cert(
    JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT),
  ),
});

const app = express();
const port = 4000;
const resend = new Resend(process.env.RESEND_API_KEY);

app.use(cors());
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb" }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// GET /banks — fetch supported Nigerian banks from Paystack (always up-to-date codes)
app.get("/banks", async (req, res) => {
  try {
    const r = await fetch(
      "https://api.paystack.co/bank?country=nigeria&type=nuban&currency=NGN&per_page=100",
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      },
    );
    const data = await r.json();
    if (data.status) {
      const banks = data.data.map((b) => ({ name: b.name, code: b.code }));
      return res.json(banks);
    }
    res.status(500).json({ error: "Failed to fetch banks" });
  } catch (err) {
    console.error("Banks fetch error:", err);
    res.status(500).json({ error: "Request failed" });
  }
});

// GET /resolve-account — verify a merchant's bank account number before creating subaccount
app.get("/resolve-account", async (req, res) => {
  const { account_number, bank_code } = req.query;
  if (!account_number || !bank_code) {
    return res
      .status(400)
      .json({ error: "account_number and bank_code are required" });
  }
  try {
    const r = await fetch(
      `https://api.paystack.co/bank/resolve?account_number=${encodeURIComponent(account_number)}&bank_code=${encodeURIComponent(bank_code)}`,
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      },
    );
    const data = await r.json();
    if (data.status) {
      return res.json({ accountName: data.data.account_name });
    }
    return res
      .status(400)
      .json({ error: data.message || "Could not resolve account" });
  } catch (err) {
    console.error("Resolve account error:", err);
    return res.status(500).json({ error: "Request failed" });
  }
});

// POST /create-subaccount — register merchant bank account as a Paystack subaccount
app.post("/create-subaccount", async (req, res) => {
  const { businessName, bankCode, accountNumber } = req.body;
  if (!businessName || !bankCode || !accountNumber) {
    return res.status(400).json({
      error: "businessName, bankCode, and accountNumber are required",
    });
  }
  try {
    const r = await fetch("https://api.paystack.co/subaccount", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        business_name: businessName,
        settlement_bank: bankCode,
        account_number: accountNumber,
        percentage_charge: 0,
      }),
    });
    const data = await r.json();
    if (data.status) {
      return res.json({ subaccountCode: data.data.subaccount_code });
    }
    return res
      .status(400)
      .json({ error: data.message || "Subaccount creation failed" });
  } catch (err) {
    console.error("Create subaccount error:", err);
    return res.status(500).json({ error: "Request failed" });
  }
});

app.post("/verify-payment", async (req, res) => {
  const { reference } = req.body;
  if (!reference || typeof reference !== "string") {
    return res.status(400).json({ success: false, error: "Invalid reference" });
  }
  try {
    const paystackRes = await fetch(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      },
    );
    const data = await paystackRes.json();
    if (data.data?.status === "success") {
      return res.json({ success: true, amount: data.data.amount });
    }
    return res
      .status(400)
      .json({ success: false, error: "Payment not successful" });
  } catch (err) {
    console.error("Paystack verify error:", err);
    return res
      .status(500)
      .json({ success: false, error: "Verification request failed" });
  }
});

// DELETE /delete-user — permanently delete a Firebase Auth account (admin only)
app.delete("/delete-user", async (req, res) => {
  if (req.headers["x-admin-key"] !== process.env.ADMIN_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const { uid } = req.body;
  if (!uid) return res.status(400).json({ error: "uid required" });
  try {
    await admin.auth().deleteUser(uid);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST /send-receipt — email the full bill to the customer(s) when the table is closed
app.post("/send-receipt", async (req, res) => {
  const { emails, restaurantName, table, orders, totalBill } = req.body;
  if (!emails?.length) {
    return res.status(400).json({ error: "No email addresses provided" });
  }

  const itemsHtml = orders
    .map((order) => {
      const rows = (order.items || [])
        .map(
          (item) => `
        <tr>
          <td style="padding:6px 0;color:#aaa;font-size:13px;">${item.qty}× ${item.name}</td>
          <td style="padding:6px 0;text-align:right;color:#aaa;font-size:13px;">₦${(parseFloat(item.price) * item.qty).toLocaleString()}</td>
        </tr>`,
        )
        .join("");
      const header =
        orders.length > 1
          ? `<p style="color:#666;font-size:11px;margin:0 0 8px 0;text-transform:uppercase;letter-spacing:1px;">${order.customerName}'s order</p>`
          : "";
      return `
      <div style="margin-bottom:16px;">
        ${header}
        <table style="width:100%;border-collapse:collapse;">
          ${rows}
          <tr>
            <td style="padding:8px 0;border-top:1px solid #333;color:#666;font-size:12px;">Subtotal</td>
            <td style="padding:8px 0;border-top:1px solid #333;text-align:right;color:#fff;font-size:13px;font-weight:bold;">₦${Number(order.total || 0).toLocaleString()}</td>
          </tr>
        </table>
      </div>`;
    })
    .join(
      '<hr style="border:none;border-top:1px solid #222;margin:16px 0;" />',
    );

  const html = `
    <div style="background:#0a0a0a;font-family:-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;">
      <h1 style="color:#fff;font-size:22px;font-weight:900;margin:0 0 4px 0;">${restaurantName}</h1>
      <p style="color:#555;font-size:13px;margin:0 0 32px 0;">Table ${table} · Receipt</p>
      <div style="background:#111;border:1px solid #222;padding:20px;margin-bottom:16px;">${itemsHtml}</div>
      <div style="background:#111;border:1px solid #333;padding:16px 20px;display:flex;justify-content:space-between;align-items:center;">
        <span style="color:#666;font-size:14px;text-transform:uppercase;letter-spacing:1px;">Total</span>
        <span style="color:#fff;font-size:22px;font-weight:900;">₦${Number(totalBill).toLocaleString()}</span>
      </div>
      <p style="color:#333;font-size:12px;text-align:center;margin-top:32px;">Thank you for dining with us!</p>
    </div>`;

  try {
    await resend.emails.send({
      from: "SERVRR <onboarding@resend.dev>",
      to: emails,
      subject: `Your receipt from ${restaurantName} — Table ${table}`,
      html,
    });
    res.json({ success: true });
  } catch (err) {
    console.error("Receipt email error:", err);
    res.status(500).json({ error: "Failed to send email" });
  }
});

app.get("/", async (req, res) => {
  const { email, subject, message, table, order1 } = req.query;

  try {
    await resend.emails.send({
      from: "FOODco <onboarding@resend.dev>",
      to: [email, process.env.EMAIL_USER],
      subject: `${subject}'s Order`,
      html: `
        <h1>Order Summary</h1>
        <p><strong>Table number:</strong> ${table}</p>
        <p><strong>Allergies / notes:</strong> ${order1}</p>
        <h2>Your order:</h2>
        <pre>${message}</pre>
      `,
    });
    res.send("Email sent successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("An error occurred sending the email.");
  }
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
