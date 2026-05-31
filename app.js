require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
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
const db = admin.firestore();
const { FieldValue } = admin.firestore;

app.use(cors());
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb" }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

const normalizePaymentMode = (mode) =>
  mode === "pay_online" || mode === "online" ? "pay_online" : "at_table";

const slugify = (name) =>
  String(name || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 20);

const isExpiredTimestamp = (value) => {
  if (!value) return false;
  const expiry = typeof value.toDate === "function" ? value.toDate() : new Date(value);
  return Number.isFinite(expiry.getTime()) && new Date() > expiry;
};

const requireFirebaseUser = async (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing auth token" });

  try {
    req.firebaseUser = await admin.auth().verifyIdToken(token);
    return next();
  } catch (err) {
    console.error("Auth token verification failed:", err);
    return res.status(401).json({ error: "Invalid auth token" });
  }
};

const validateOrderItems = (items) => {
  if (!Array.isArray(items) || items.length === 0 || items.length > 100) {
    return false;
  }
  return items.every((item) => {
    const price = Number(item.price);
    const qty = Number(item.qty);
    return (
      typeof item.name === "string" &&
      item.name.trim().length > 0 &&
      Number.isFinite(price) &&
      price >= 0 &&
      Number.isFinite(qty) &&
      Number.isInteger(qty) &&
      qty > 0 &&
      qty <= 100
    );
  });
};

const calculateItemsTotal = (items) =>
  items.reduce((sum, item) => sum + Number(item.price) * Number(item.qty), 0);

const verifyPaystackReference = async (reference) => {
  const paystackRes = await fetch(
    `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
    {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
    },
  );
  const data = await paystackRes.json();
  if (!paystackRes.ok || data.data?.status !== "success") {
    const message = data.message || "Payment not successful";
    const error = new Error(message);
    error.statusCode = 400;
    throw error;
  }
  return data.data;
};

app.post("/complete-signup", requireFirebaseUser, async (req, res) => {
  const {
    inviteCode,
    name,
    paymentMode,
    accentColor,
    tagline,
    description,
    logoUrl,
    address,
    phone,
    contactEmail,
    instagram,
    twitter,
  } = req.body || {};

  const email = req.firebaseUser.email;
  const uid = req.firebaseUser.uid;
  const restaurantId = slugify(name);
  const selectedPaymentMode = normalizePaymentMode(paymentMode);

  if (!inviteCode || !name || !restaurantId || !email) {
    return res.status(400).json({ error: "Invite code, restaurant name, and email are required." });
  }
  if (!address || !phone || !contactEmail) {
    return res.status(400).json({ error: "Address, phone, and contact email are required." });
  }

  try {
    const result = await db.runTransaction(async (tx) => {
      const userRef = db.doc(`users/${uid}`);
      const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
      const inviteQuery = db
        .collection("inviteCodes")
        .where("code", "==", String(inviteCode).trim().toUpperCase())
        .where("status", "==", "unused")
        .limit(1);

      const [userSnap, profileSnap, inviteSnap] = await Promise.all([
        tx.get(userRef),
        tx.get(profileRef),
        tx.get(inviteQuery),
      ]);

      if (userSnap.exists) {
        throw Object.assign(new Error("This user already has a restaurant workspace."), { statusCode: 409 });
      }
      if (profileSnap.exists) {
        throw Object.assign(new Error("This restaurant URL is already taken. Please adjust the name."), { statusCode: 409 });
      }
      if (inviteSnap.empty) {
        throw Object.assign(new Error("Invalid or already used invite code."), { statusCode: 400 });
      }

      const inviteDoc = inviteSnap.docs[0];
      const inviteData = inviteDoc.data();
      if (isExpiredTimestamp(inviteData.expiresAt)) {
        throw Object.assign(new Error("This invite code has expired."), { statusCode: 400 });
      }

      const trialEndsAt = new Date();
      trialEndsAt.setDate(trialEndsAt.getDate() + 7);

      tx.set(userRef, {
        restaurantId,
        email,
        role: "owner",
        createdAt: FieldValue.serverTimestamp(),
      });

      tx.set(profileRef, {
        restaurantId,
        ownerUid: uid,
        name: String(name).trim(),
        email,
        accentColor: accentColor || "#fa5631",
        tagline: tagline || "",
        description: description || "",
        logoUrl: logoUrl || "",
        address,
        phone,
        contactEmail,
        instagram: instagram || "",
        twitter: twitter || "",
        paymentPreference: selectedPaymentMode,
        paymentMode: selectedPaymentMode,
        paymentModeUpdatedAt: FieldValue.serverTimestamp(),
        subscriptionStatus: "trial",
        trialEndsAt,
        subscriptionPaidUntil: null,
        createdAt: FieldValue.serverTimestamp(),
      });

      tx.update(inviteDoc.ref, {
        status: "used",
        usedBy: restaurantId,
        usedByUid: uid,
        usedAt: FieldValue.serverTimestamp(),
      });

      return { restaurantId };
    });

    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Complete signup error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Signup setup failed. Please try again.",
    });
  }
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

app.post("/paystack-webhook", async (req, res) => {
  const signature = req.headers["x-paystack-signature"];
  const hash = crypto
    .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
    .update(JSON.stringify(req.body))
    .digest("hex");

  if (!signature || hash !== signature) {
    return res.status(401).send("Invalid signature");
  }

  const event = req.body;
  const transaction = event?.data || {};
  const reference = transaction.reference;

  if (!reference) return res.sendStatus(200);

  try {
    const metadata = transaction.metadata || {};
    await db.doc(`paymentReferences/${reference}`).set(
      {
        reference,
        event: event.event || null,
        status: transaction.status || null,
        amount: Number(transaction.amount || 0),
        currency: transaction.currency || null,
        restaurantId: metadata.restaurantId || null,
        table: metadata.table || null,
        customerName: metadata.customerName || null,
        paidAt: transaction.paid_at ? new Date(transaction.paid_at) : null,
        raw: transaction,
        webhookReceivedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
  } catch (err) {
    console.error("Paystack webhook persistence error:", err);
    return res.sendStatus(500);
  }

  return res.sendStatus(200);
});

app.post("/finalize-online-payment", async (req, res) => {
  const {
    reference,
    restaurantId,
    customerName,
    email,
    table,
    allergies,
    items,
    total,
    sessionId,
  } = req.body || {};

  const cleanedReference = String(reference || "").trim();
  const cleanedRestaurantId = String(restaurantId || "").trim();
  const cleanedTable = String(table || "").trim();
  const cleanedName = String(customerName || "").trim();
  const numericTotal = Number(total);
  const expectedAmount = Math.round(numericTotal * 100);
  const cleanedItems = Array.isArray(items)
    ? items.map((item) => ({
        name: String(item.name || "").trim(),
        price: Number(item.price),
        qty: Number(item.qty),
      }))
    : [];

  if (!cleanedReference || !cleanedRestaurantId || !cleanedTable || !cleanedName) {
    return res.status(400).json({ success: false, error: "Missing payment or order details." });
  }
  if (!Number.isFinite(numericTotal) || numericTotal <= 0 || expectedAmount <= 0) {
    return res.status(400).json({ success: false, error: "Invalid order total." });
  }
  if (!validateOrderItems(cleanedItems)) {
    return res.status(400).json({ success: false, error: "Invalid order items." });
  }

  const calculatedTotal = calculateItemsTotal(cleanedItems);
  if (Math.round(calculatedTotal * 100) !== expectedAmount) {
    return res.status(400).json({ success: false, error: "Order total does not match items." });
  }

  try {
    const transaction = await verifyPaystackReference(cleanedReference);
    const metadata = transaction.metadata || {};

    if (Number(transaction.amount) !== expectedAmount) {
      return res.status(400).json({ success: false, error: "Payment amount does not match order total." });
    }
    if (transaction.currency !== "NGN") {
      return res.status(400).json({ success: false, error: "Unsupported payment currency." });
    }
    if (metadata.restaurantId && metadata.restaurantId !== cleanedRestaurantId) {
      return res.status(400).json({ success: false, error: "Payment restaurant mismatch." });
    }
    if (metadata.table && String(metadata.table) !== cleanedTable) {
      return res.status(400).json({ success: false, error: "Payment table mismatch." });
    }

    const result = await db.runTransaction(async (tx) => {
      const profileRef = db.doc(`restaurants/${cleanedRestaurantId}/profile/info`);
      const paymentRef = db.doc(`paymentReferences/${cleanedReference}`);
      const profileSnap = await tx.get(profileRef);
      const paymentSnap = await tx.get(paymentRef);

      if (!profileSnap.exists) {
        throw Object.assign(new Error("Restaurant not found."), { statusCode: 404 });
      }

      const profile = profileSnap.data();
      if (normalizePaymentMode(profile.paymentMode) !== "pay_online") {
        throw Object.assign(new Error("Online payment is not enabled for this restaurant."), { statusCode: 403 });
      }
      if (!profile.paystackSubaccountCode) {
        throw Object.assign(new Error("Online payment account is not connected."), { statusCode: 400 });
      }

      const transactionSubaccount =
        transaction.subaccount?.subaccount_code ||
        transaction.subaccount_code ||
        null;
      if (transactionSubaccount && transactionSubaccount !== profile.paystackSubaccountCode) {
        throw Object.assign(new Error("Payment account mismatch."), { statusCode: 400 });
      }

      if (paymentSnap.exists && paymentSnap.data().orderId) {
        return {
          orderId: paymentSnap.data().orderId,
          sessionId: paymentSnap.data().sessionId || null,
          reused: true,
        };
      }

      const orderRef = db.collection(`restaurants/${cleanedRestaurantId}/orders`).doc();
      let sessionRef;
      let existingOrderIds = [];
      let nextTotalBill = numericTotal;

      if (sessionId) {
        sessionRef = db.doc(`restaurants/${cleanedRestaurantId}/tableSessions/${sessionId}`);
        const sessionSnap = await tx.get(sessionRef);
        if (!sessionSnap.exists) {
          throw Object.assign(new Error("Table session not found."), { statusCode: 404 });
        }
        const session = sessionSnap.data();
        if (String(session.table) !== cleanedTable) {
          throw Object.assign(new Error("Table session mismatch."), { statusCode: 400 });
        }
        existingOrderIds = Array.isArray(session.orderIds) ? session.orderIds : [];
        nextTotalBill = Number(session.totalBill || 0) + numericTotal;
      } else {
        sessionRef = db.collection(`restaurants/${cleanedRestaurantId}/tableSessions`).doc();
      }

      tx.set(orderRef, {
        customerName: cleanedName,
        email: String(email || "").trim(),
        table: cleanedTable,
        allergies: String(allergies || "").trim(),
        items: cleanedItems,
        total: numericTotal,
        status: "pending",
        paymentStatus: "paid",
        paymentRef: cleanedReference,
        sessionId: sessionRef.id,
        createdAt: FieldValue.serverTimestamp(),
      });

      tx.set(
        sessionRef,
        {
          table: cleanedTable,
          status: "paid",
          openedAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
          paidAt: FieldValue.serverTimestamp(),
          closedAt: FieldValue.serverTimestamp(),
          totalBill: nextTotalBill,
          orderIds: [...existingOrderIds, orderRef.id],
          paymentMode: "pay_online",
          paymentStatus: "paid",
          paymentRef: cleanedReference,
        },
        { merge: true },
      );

      tx.set(
        paymentRef,
        {
          reference: cleanedReference,
          status: "success",
          amount: Number(transaction.amount),
          currency: transaction.currency,
          restaurantId: cleanedRestaurantId,
          table: cleanedTable,
          customerName: cleanedName,
          orderId: orderRef.id,
          sessionId: sessionRef.id,
          finalizedAt: FieldValue.serverTimestamp(),
          paystackData: transaction,
        },
        { merge: true },
      );

      return { orderId: orderRef.id, sessionId: sessionRef.id, reused: false };
    });

    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Finalize online payment error:", err);
    return res.status(err.statusCode || 500).json({
      success: false,
      error: err.message || "Could not finalize payment.",
    });
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
