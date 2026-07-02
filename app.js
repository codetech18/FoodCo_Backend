require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Resend } = require("resend");
const admin = require("firebase-admin");

//admin.initializeApp({
//  credential: admin.credential.cert(
//    JSON.parse(
//      (process.env.FIREBASE_SERVICE_ACCOUNT || "").replace(/\\n/g, "\n"),
//    ),
//  ),
//});

let firebaseConfig = process.env.FIREBASE_SERVICE_ACCOUNT || "";

// Remove all whitespace newlines and tabs, but preserve \n as literal characters
firebaseConfig = firebaseConfig.replace(/\s+/g, " ").trim();

admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(firebaseConfig)),
});

const app = express();
const port = 4000;
const resend = new Resend(process.env.RESEND_API_KEY);
// Sender for all transactional email. Set MAIL_FROM to your verified Resend domain,
// e.g. "Servrr <welcome@servrr.ng>". Falls back to the sandbox if unset (goes to spam).
const MAIL_FROM = process.env.MAIL_FROM || "Servrr <onboarding@resend.dev>";
const APP_URL = process.env.APP_URL || "https://servrr.ng";
const db = admin.firestore();
const { FieldValue } = admin.firestore;

// Behind Render's proxy — needed for req.ip (rate limiting) to be the real client IP.
app.set("trust proxy", 1);

// ── CORS ───────────────────────────────────────────────────────────────────────
// Set ALLOWED_ORIGINS (comma-separated) in the environment to lock the API to your
// real frontend origins. If unset, falls back to permissive (logged) so nothing breaks.
// Origins are normalized (trailing slashes, stray quotes, case) so near-miss values still match.
const normalizeOrigin = (o) =>
  String(o || "")
    .trim()
    .replace(/^['"]|['"]$/g, "")
    .replace(/\/+$/, "")
    .toLowerCase();

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(normalizeOrigin)
  .filter(Boolean);

if (ALLOWED_ORIGINS.length === 0) {
  console.warn(
    "[cors] ALLOWED_ORIGINS not set — allowing all origins. Set it to lock down CORS in production.",
  );
} else {
  console.log(`[cors] allowed origins: ${ALLOWED_ORIGINS.join(", ")}`);
}

app.use(
  cors({
    origin(origin, cb) {
      // Non-browser / same-origin requests (no Origin header) are always allowed.
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(normalizeOrigin(origin))) return cb(null, true);
      console.warn(
        `[cors] rejected origin "${origin}" — allowed: ${ALLOWED_ORIGINS.join(", ")}`,
      );
      // Deny by omitting CORS headers (browser blocks) rather than erroring with a 500.
      return cb(null, false);
    },
  }),
);

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb" }));

// ── Rate limiting ──────────────────────────────────────────────────────────────
// Lightweight in-memory fixed-window limiter (sufficient for a single instance;
// use a shared store like Redis if the backend is ever horizontally scaled).
const rateBuckets = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of rateBuckets) if (now > b.reset) rateBuckets.delete(k);
}, 60_000).unref?.();

const rateLimit = ({ windowMs, max }) => (req, res, next) => {
  const key = `${req.method} ${req.path}:${req.ip}`;
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now > bucket.reset) {
    bucket = { count: 0, reset: now + windowMs };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  if (bucket.count > max) {
    res.setHeader("Retry-After", String(Math.ceil((bucket.reset - now) / 1000)));
    return res
      .status(429)
      .json({ error: "Too many requests. Please slow down and try again shortly." });
  }
  return next();
};

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
  const expiry =
    typeof value.toDate === "function" ? value.toDate() : new Date(value);
  return Number.isFinite(expiry.getTime()) && new Date() > expiry;
};

const toMillis = (ts) => {
  if (!ts) return 0;
  if (typeof ts.toDate === "function") return ts.toDate().getTime();
  if (ts.seconds) return ts.seconds * 1000;
  const d = new Date(ts).getTime();
  return Number.isFinite(d) ? d : 0;
};

// 3-day grace period after a trial/subscription lapses — venue keeps working while
// the owner is nudged to pay; the daily sweep suspends only after grace runs out.
const GRACE_MS = 3 * 24 * 60 * 60 * 1000;

// Whether a venue may currently take orders — mirrors the client gating in
// RestaurantContext so a lapsed/suspended venue can't be ordered from via the API.
const isVenueActive = (profile) => {
  if (!profile) return false;
  if (profile.suspended === true) return false;
  // Legacy venues created before the subscription system are grandfathered active.
  const hasSubFields =
    profile.trialEndsAt ||
    profile.subscriptionPaidUntil ||
    profile.plan ||
    profile.businessType;
  if (!hasSubFields) return true;
  const now = Date.now();
  const lapseAt = Math.max(toMillis(profile.trialEndsAt), toMillis(profile.subscriptionPaidUntil));
  return now < lapseAt + GRACE_MS;
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

// Mirrors isSuperAdmin/ownsRestaurantProfile/hasRestaurantRole in Functions/firestore.rules —
// Admin SDK calls bypass rules, so staff-only routes re-check the same access model here.
const SUPER_ADMIN_UID = "vqjNAPsGMyUjVL7PMIg3cBNSQhS2";
const OPS_ROLES = ["owner", "manager", "admin", "staff", "kitchen", "bar", "waiter", "cashier"];
const MANAGE_ROLES = ["owner", "manager", "admin"];

// Escape user-supplied strings before interpolating into HTML emails.
const escapeHtml = (value) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

// Mirrors isSuperAdmin in firestore.rules — the hardcoded UID OR a users doc with role "superadmin".
const isSuperAdmin = async (uid) => {
  if (uid === SUPER_ADMIN_UID) return true;
  const snap = await db.doc(`users/${uid}`).get();
  return snap.exists && snap.data().role === "superadmin";
};

const hasRestaurantAccess = async (uid, restaurantId, roles) => {
  if (await isSuperAdmin(uid)) return true;

  const profileSnap = await db.doc(`restaurants/${restaurantId}/profile/info`).get();
  if (profileSnap.exists && profileSnap.data().ownerUid === uid) return true;

  const userSnap = await db.doc(`users/${uid}`).get();
  if (!userSnap.exists) return false;
  const userData = userSnap.data();
  return userData.restaurantId === restaurantId && roles.includes(userData.role);
};

// Any operational staff (mirrors canViewRestaurantOps).
const userCanOperate = (uid, restaurantId) =>
  hasRestaurantAccess(uid, restaurantId, OPS_ROLES);

// Management only (mirrors canManageRestaurant) — owner/manager/admin.
const userCanManage = (uid, restaurantId) =>
  hasRestaurantAccess(uid, restaurantId, MANAGE_ROLES);

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

// Generate a Firebase email-verification link. Tries to send the user back to the
// app's /login afterwards; falls back to the default handler if that domain isn't
// in Firebase's authorized domains yet.
const genVerifyLink = async (email) => {
  try {
    return await admin.auth().generateEmailVerificationLink(email, {
      url: `${APP_URL}/login`,
      handleCodeInApp: false,
    });
  } catch (_) {
    return admin.auth().generateEmailVerificationLink(email);
  }
};

// Branded welcome + email-verification message, sent via Resend from the verified domain.
const sendWelcomeEmail = async (email, name, verifyLink) => {
  const safeName = escapeHtml(name || "there");
  const html = `
    <div style="background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:480px;margin:0 auto;padding:40px 28px;">
      <p style="color:#fa5631;font-size:22px;font-weight:900;letter-spacing:-0.5px;margin:0 0 28px 0;">SERVRR</p>
      <h1 style="color:#fff;font-size:24px;font-weight:800;margin:0 0 12px 0;">Welcome, ${safeName} 👋</h1>
      <p style="color:#aaa;font-size:14px;line-height:1.6;margin:0 0 24px 0;">
        Your restaurant workspace is ready. One quick step to activate it — confirm your email address:
      </p>
      <a href="${verifyLink}" style="display:inline-block;background:#fa5631;color:#0a0a0a;font-size:14px;font-weight:800;text-decoration:none;padding:14px 32px;border-radius:10px;margin-bottom:28px;">
        Verify my email
      </a>
      <div style="background:#111;border:1px solid #222;border-radius:14px;padding:20px;margin:8px 0 24px 0;">
        <p style="color:#666;font-size:11px;text-transform:uppercase;letter-spacing:1px;font-weight:700;margin:0 0 12px 0;">What's next</p>
        <p style="color:#ccc;font-size:13px;line-height:1.7;margin:0;">
          1. Verify your email (button above)<br/>
          2. Log in to your dashboard<br/>
          3. Add your menu &amp; generate table QR codes<br/>
          4. Start taking orders
        </p>
      </div>
      <p style="color:#555;font-size:11px;line-height:1.5;margin:0;word-break:break-all;">
        If the button doesn't work, paste this link into your browser:<br/>${verifyLink}
      </p>
      <p style="color:#333;font-size:11px;text-align:center;margin-top:32px;">© ${new Date().getFullYear()} SERVRR</p>
    </div>`;

  await resend.emails.send({
    from: MAIL_FROM,
    to: [email],
    subject: "Welcome to Servrr — verify your email",
    html,
  });
};

// Small branded template for billing lifecycle emails (trial ending, payment due).
const sendBillingEmail = async ({ to, subject, heading, message, restaurantId }) => {
  const html = `
    <div style="background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:480px;margin:0 auto;padding:40px 28px;">
      <p style="color:#fa5631;font-size:22px;font-weight:900;letter-spacing:-0.5px;margin:0 0 28px 0;">SERVRR</p>
      <h1 style="color:#fff;font-size:22px;font-weight:800;margin:0 0 12px 0;">${escapeHtml(heading)}</h1>
      <p style="color:#aaa;font-size:14px;line-height:1.7;margin:0 0 24px 0;">${message}</p>
      <a href="${APP_URL}/${encodeURIComponent(restaurantId)}/admin" style="display:inline-block;background:#fa5631;color:#0a0a0a;font-size:14px;font-weight:800;text-decoration:none;padding:14px 32px;border-radius:10px;margin-bottom:24px;">
        Open my dashboard
      </a>
      <p style="color:#555;font-size:12px;line-height:1.6;margin:0;">
        To pay: reply to this email or message us on WhatsApp — payment is confirmed within 2 hours.
      </p>
      <p style="color:#333;font-size:11px;text-align:center;margin-top:32px;">© ${new Date().getFullYear()} SERVRR</p>
    </div>`;
  await resend.emails.send({ from: MAIL_FROM, to: [to], subject, html });
};

// ── Subscription sweep ───────────────────────────────────────────────────────────
// Runs in-process (Cloud Functions need the Blaze plan): reminds owners 2 days before
// trial ends, notifies on lapse (grace starts), suspends after grace, and reactivates
// renewed venues. Idempotent via marker fields on the profile; safe to run repeatedly.
const TRIAL_REMINDER_MS = 2 * 24 * 60 * 60 * 1000;
let sweepRunning = false;

const runSubscriptionSweep = async () => {
  if (sweepRunning) return;
  sweepRunning = true;
  try {
    const usersSnap = await db.collection("users").where("role", "==", "owner").get();
    const seen = new Set();
    const now = Date.now();

    for (const userDoc of usersSnap.docs) {
      const { restaurantId } = userDoc.data();
      if (!restaurantId || seen.has(restaurantId)) continue;
      seen.add(restaurantId);

      const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
      const snap = await profileRef.get();
      if (!snap.exists) continue;
      const p = snap.data();

      // Legacy venues and manual suspensions are left alone.
      const hasSubFields = p.trialEndsAt || p.subscriptionPaidUntil || p.plan || p.businessType;
      if (!hasSubFields) continue;
      if (p.suspended === true && p.suspendedReason === "manual") continue;

      const ownerEmail = p.email || userDoc.data().email;
      const trialEnd = toMillis(p.trialEndsAt);
      const paidUntil = toMillis(p.subscriptionPaidUntil);
      const lapseAt = Math.max(trialEnd, paidUntil);
      const inTrial = now < trialEnd;
      const isPaid = now < paidUntil;

      try {
        // 1. Trial ending in <= 2 days → one reminder, ever.
        if (
          inTrial &&
          !isPaid &&
          trialEnd - now <= TRIAL_REMINDER_MS &&
          !p.trialReminderSentAt &&
          ownerEmail
        ) {
          const daysLeft = Math.max(1, Math.ceil((trialEnd - now) / 86400000));
          await sendBillingEmail({
            to: ownerEmail,
            subject: `Your Servrr trial ends in ${daysLeft} day${daysLeft > 1 ? "s" : ""}`,
            heading: "Your free trial is almost up",
            message: `Your trial for <strong style="color:#fff">${escapeHtml(p.name || restaurantId)}</strong> ends in ${daysLeft} day${daysLeft > 1 ? "s" : ""}. Activate your subscription now so your QR ordering keeps running without interruption.`,
            restaurantId,
          });
          await profileRef.update({ trialReminderSentAt: FieldValue.serverTimestamp() });
        }

        // 2. Just lapsed (grace window) → one notice per lapse (re-arms after each renewal).
        if (!inTrial && !isPaid && now < lapseAt + GRACE_MS) {
          if (p.expiryNoticeForLapse !== lapseAt && ownerEmail) {
            await sendBillingEmail({
              to: ownerEmail,
              subject: "Action needed — your Servrr subscription has expired",
              heading: "Payment due",
              message: `The subscription for <strong style="color:#fff">${escapeHtml(p.name || restaurantId)}</strong> has expired. Your restaurant keeps working for a 3-day grace period — after that, ordering pauses until payment is confirmed.`,
              restaurantId,
            });
            await profileRef.update({ expiryNoticeForLapse: lapseAt });
          }
        }

        // 3. Past grace → suspend.
        if (!inTrial && !isPaid && now >= lapseAt + GRACE_MS && p.suspended !== true) {
          await profileRef.update({
            suspended: true,
            suspendedReason: "subscription_expired",
            suspendedAt: FieldValue.serverTimestamp(),
            subscriptionStatus: "expired",
          });
          console.log(`[sweep] suspended ${restaurantId} (lapsed ${new Date(lapseAt).toISOString()})`);
        }

        // 4. Renewed while auto-suspended → reactivate.
        if ((inTrial || isPaid) && p.suspended === true && p.suspendedReason === "subscription_expired") {
          await profileRef.update({
            suspended: false,
            suspendedReason: null,
            subscriptionStatus: isPaid ? "active" : "trial",
          });
          console.log(`[sweep] reactivated ${restaurantId}`);
        }
      } catch (err) {
        console.error(`[sweep] error for ${restaurantId}:`, err);
      }
    }
  } catch (err) {
    console.error("[sweep] failed:", err);
  } finally {
    sweepRunning = false;
  }
};

// Kick off shortly after boot (Render restarts often, so boot-time runs keep it fresh),
// then every 6 hours while the instance is awake.
setTimeout(runSubscriptionSweep, 30_000).unref?.();
setInterval(runSubscriptionSweep, 6 * 60 * 60 * 1000).unref?.();

app.post("/complete-signup", rateLimit({ windowMs: 15 * 60_000, max: 20 }), requireFirebaseUser, async (req, res) => {
  const {
    inviteCode,
    name,
    businessType,
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
  // Only restaurant/lounge are sellable today; anything else (incl. "hotel") falls back to restaurant.
  const selectedBusinessType =
    businessType === "lounge" ? "lounge" : "restaurant";

  if (!inviteCode || !name || !restaurantId || !email) {
    return res
      .status(400)
      .json({ error: "Invite code, restaurant name, and email are required." });
  }
  if (!address || !phone || !contactEmail) {
    return res
      .status(400)
      .json({ error: "Address, phone, and contact email are required." });
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
        throw Object.assign(
          new Error("This user already has a restaurant workspace."),
          { statusCode: 409 },
        );
      }
      if (profileSnap.exists) {
        throw Object.assign(
          new Error(
            "This restaurant URL is already taken. Please adjust the name.",
          ),
          { statusCode: 409 },
        );
      }
      if (inviteSnap.empty) {
        throw Object.assign(new Error("Invalid or already used invite code."), {
          statusCode: 400,
        });
      }

      const inviteDoc = inviteSnap.docs[0];
      const inviteData = inviteDoc.data();
      if (isExpiredTimestamp(inviteData.expiresAt)) {
        throw Object.assign(new Error("This invite code has expired."), {
          statusCode: 400,
        });
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
        businessType: selectedBusinessType,
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
        suspended: false,
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

    // Send the branded welcome + verification email — non-blocking (don't fail
    // signup if email delivery has a hiccup; the login page can resend).
    try {
      const verifyLink = await genVerifyLink(email);
      await sendWelcomeEmail(email, name, verifyLink);
    } catch (mailErr) {
      console.error("Welcome email failed:", mailErr);
    }

    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Complete signup error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Signup setup failed. Please try again.",
    });
  }
});

// POST /resend-verification — re-send the branded verification email to the signed-in user.
app.post(
  "/resend-verification",
  rateLimit({ windowMs: 60_000, max: 5 }),
  requireFirebaseUser,
  async (req, res) => {
    const email = req.firebaseUser.email;
    if (!email) return res.status(400).json({ error: "No email on this account." });
    try {
      const verifyLink = await genVerifyLink(email);
      await sendWelcomeEmail(email, req.firebaseUser.name, verifyLink);
      return res.json({ success: true });
    } catch (err) {
      console.error("Resend verification failed:", err);
      return res.status(500).json({ error: "Could not resend verification email." });
    }
  },
);

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

// GET /resolve-account — verify a merchant's bank account number before creating subaccount (management only)
app.get("/resolve-account", rateLimit({ windowMs: 60_000, max: 30 }), requireFirebaseUser, async (req, res) => {
  const { account_number, bank_code, restaurantId } = req.query;
  const cleanedRestaurantId = String(restaurantId || "").trim();
  if (!account_number || !bank_code) {
    return res
      .status(400)
      .json({ error: "account_number and bank_code are required" });
  }
  if (!cleanedRestaurantId) {
    return res.status(400).json({ error: "restaurantId is required" });
  }
  if (!(await userCanManage(req.firebaseUser.uid, cleanedRestaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
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

// POST /create-subaccount — register merchant bank account as a Paystack subaccount (management only)
app.post("/create-subaccount", rateLimit({ windowMs: 60_000, max: 10 }), requireFirebaseUser, async (req, res) => {
  const { businessName, bankCode, accountNumber, restaurantId } = req.body;
  const cleanedRestaurantId = String(restaurantId || "").trim();
  if (!businessName || !bankCode || !accountNumber) {
    return res.status(400).json({
      error: "businessName, bankCode, and accountNumber are required",
    });
  }
  if (!cleanedRestaurantId) {
    return res.status(400).json({ error: "restaurantId is required" });
  }
  if (!(await userCanManage(req.firebaseUser.uid, cleanedRestaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
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

// GET /table-token — mint (or fetch) the permanent per-table QR secret (staff only)
app.get("/table-token", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  const table = String(req.query.table || "").trim();
  if (!restaurantId || !table) {
    return res.status(400).json({ error: "restaurantId and table are required" });
  }

  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant" });
    }

    const token = await db.runTransaction(async (tx) => {
      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${table}`);
      const tableSnap = await tx.get(tableRef);
      if (tableSnap.exists && tableSnap.data().token) {
        return tableSnap.data().token;
      }

      const newToken = crypto.randomBytes(16).toString("hex");
      tx.set(
        tableRef,
        {
          token: newToken,
          currentSessionId: tableSnap.exists ? tableSnap.data().currentSessionId ?? null : null,
          createdAt: tableSnap.exists ? tableSnap.data().createdAt : FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        },
        { merge: true },
      );
      return newToken;
    });

    return res.json({ token });
  } catch (err) {
    console.error("Table token error:", err);
    return res.status(500).json({ error: "Could not fetch table token." });
  }
});

// GET /table-tokens?restaurantId=&count= — mint/fetch tokens for tables 1..count in ONE
// request (the per-table route above does a round trip per table, which is painfully slow
// from high-latency connections). Staff only.
app.get("/table-tokens", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  const count = Math.min(100, Math.max(1, Number(req.query.count) || 0));
  if (!restaurantId || !count) {
    return res.status(400).json({ error: "restaurantId and count are required" });
  }

  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant" });
    }

    const refs = Array.from({ length: count }, (_, i) =>
      db.doc(`restaurants/${restaurantId}/tables/${i + 1}`),
    );
    const snaps = await db.getAll(...refs);

    const tokens = {};
    const batch = db.batch();
    let mintedAny = false;
    snaps.forEach((snap, i) => {
      const table = i + 1;
      if (snap.exists && snap.data().token) {
        tokens[table] = snap.data().token;
        return;
      }
      const newToken = crypto.randomBytes(16).toString("hex");
      tokens[table] = newToken;
      mintedAny = true;
      batch.set(
        snap.ref,
        {
          token: newToken,
          currentSessionId: snap.exists ? snap.data().currentSessionId ?? null : null,
          createdAt: snap.exists ? snap.data().createdAt : FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        },
        { merge: true },
      );
    });
    if (mintedAny) await batch.commit();

    return res.json({ tokens });
  } catch (err) {
    console.error("Table tokens error:", err);
    return res.status(500).json({ error: "Could not fetch table tokens." });
  }
});

// POST /open-table-session — validate the permanent QR token and open/rejoin a session (public, QR scan)
app.post("/open-table-session", rateLimit({ windowMs: 60_000, max: 60 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const table = String(req.body?.table || "").trim();
  const token = String(req.body?.token || "").trim();
  if (!restaurantId || !table || !token) {
    return res.status(400).json({ error: "restaurantId, table, and token are required" });
  }

  try {
    const sessionId = await db.runTransaction(async (tx) => {
      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${table}`);
      const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
      const [tableSnap, profileSnap] = await Promise.all([
        tx.get(tableRef),
        tx.get(profileRef),
      ]);
      if (!tableSnap.exists || tableSnap.data().token !== token) {
        throw Object.assign(new Error("Invalid table QR code."), { statusCode: 403 });
      }

      // Block ordering at suspended or lapsed-subscription venues.
      if (!isVenueActive(profileSnap.data())) {
        throw Object.assign(
          new Error("This restaurant isn't accepting orders right now."),
          { statusCode: 403 },
        );
      }

      const currentSessionId = tableSnap.data().currentSessionId || null;
      if (currentSessionId) {
        const sessionRef = db.doc(
          `restaurants/${restaurantId}/tableSessions/${currentSessionId}`,
        );
        const sessionSnap = await tx.get(sessionRef);
        if (
          sessionSnap.exists &&
          ["open", "awaiting_payment"].includes(sessionSnap.data().status)
        ) {
          return currentSessionId;
        }
      }

      const paymentMode = normalizePaymentMode(profileSnap.data()?.paymentMode);

      const newSessionRef = db
        .collection(`restaurants/${restaurantId}/tableSessions`)
        .doc();
      tx.set(newSessionRef, {
        table,
        status: "open",
        openedAt: FieldValue.serverTimestamp(),
        billRequestedAt: null,
        closedAt: null,
        totalBill: 0,
        orderIds: [],
        paymentMode,
        paidVia: null,
        closedByUid: null,
      });
      tx.set(
        tableRef,
        { currentSessionId: newSessionRef.id, updatedAt: FieldValue.serverTimestamp() },
        { merge: true },
      );
      return newSessionRef.id;
    });

    return res.json({ sessionId });
  } catch (err) {
    console.error("Open table session error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not open table session.",
    });
  }
});

// POST /request-bill — customer-triggered soft lock, idempotent (public)
app.post("/request-bill", async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  if (!restaurantId || !sessionId) {
    return res.status(400).json({ error: "restaurantId and sessionId are required" });
  }

  try {
    const status = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists) {
        throw Object.assign(new Error("Table session not found."), { statusCode: 404 });
      }

      const session = sessionSnap.data();
      if (session.status !== "open") {
        return session.status;
      }

      tx.update(sessionRef, {
        status: "awaiting_payment",
        billRequestedAt: FieldValue.serverTimestamp(),
      });
      return "awaiting_payment";
    });

    return res.json({ status });
  } catch (err) {
    console.error("Request bill error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not request bill.",
    });
  }
});

// POST /call-waiter — diner-triggered, flags the session so staff get an alert (public)
app.post("/call-waiter", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  if (!restaurantId || !sessionId) {
    return res.status(400).json({ error: "restaurantId and sessionId are required" });
  }

  try {
    await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists) {
        throw Object.assign(new Error("Table session not found."), { statusCode: 404 });
      }
      const session = sessionSnap.data();
      if (!["open", "awaiting_payment"].includes(session.status)) {
        throw Object.assign(new Error("This table's session is closed."), { statusCode: 409 });
      }
      tx.update(sessionRef, { waiterCalledAt: FieldValue.serverTimestamp() });
    });

    return res.json({ success: true });
  } catch (err) {
    console.error("Call waiter error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not call the waiter.",
    });
  }
});

// POST /close-table-session — staff-only, the only path to mark a table paid
app.post("/close-table-session", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const paidVia = req.body?.paidVia;
  const total = Number(req.body?.total);

  if (!restaurantId || !sessionId) {
    return res.status(400).json({ error: "restaurantId and sessionId are required" });
  }
  if (!["cash", "pos"].includes(paidVia)) {
    return res.status(400).json({ error: "paidVia must be 'cash' or 'pos'" });
  }
  if (!Number.isFinite(total) || total < 0) {
    return res.status(400).json({ error: "Invalid confirmed total." });
  }

  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant" });
    }

    const receipt = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists) {
        throw Object.assign(new Error("Table session not found."), { statusCode: 404 });
      }
      const session = sessionSnap.data();
      if (session.status === "paid") {
        throw Object.assign(new Error("Table session is already closed."), {
          statusCode: 409,
        });
      }

      const orderIds = Array.isArray(session.orderIds) ? session.orderIds : [];
      const orderRefs = orderIds.map((id) =>
        db.doc(`restaurants/${restaurantId}/orders/${id}`),
      );
      const orderSnaps = orderRefs.length
        ? await Promise.all(orderRefs.map((ref) => tx.get(ref)))
        : [];
      const profileSnap = await tx.get(db.doc(`restaurants/${restaurantId}/profile/info`));

      tx.update(sessionRef, {
        status: "paid",
        closedAt: FieldValue.serverTimestamp(),
        paidVia,
        closedByUid: req.firebaseUser.uid,
        totalBill: total,
        // Bill settled — any outstanding "call waiter" is answered by definition.
        waiterCalledAt: null,
      });

      orderSnaps.forEach((snap) => {
        if (snap.exists) tx.update(snap.ref, { paymentStatus: "paid" });
      });

      tx.set(
        db.doc(`restaurants/${restaurantId}/tables/${session.table}`),
        { currentSessionId: null, updatedAt: FieldValue.serverTimestamp() },
        { merge: true },
      );

      // Receipt bills are grouped per guest: same email = one bill, different
      // guests (email, else name) stay separate.
      const groups = new Map();
      orderSnaps
        .filter((snap) => snap.exists)
        .forEach((snap) => {
          const o = snap.data();
          const email = String(o.email || "").trim().toLowerCase();
          const name = String(o.customerName || "").trim().toLowerCase();
          const key = email ? `e:${email}` : name ? `n:${name}` : `o:${snap.id}`;
          if (!groups.has(key)) {
            groups.set(key, {
              customerName: o.customerName || "Guest",
              items: [],
              total: 0,
            });
          }
          const g = groups.get(key);
          g.items.push(...(o.items || []));
          g.total += Number(o.total || 0);
        });

      return {
        restaurantName: profileSnap.data()?.name || restaurantId,
        table: session.table,
        orders: [...groups.values()],
        totalBill: total,
        paidVia,
        closedAt: new Date().toISOString(),
      };
    });

    return res.json({ success: true, ...receipt });
  } catch (err) {
    console.error("Close table session error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not close table session.",
    });
  }
});

app.post("/finalize-online-payment", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
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

  if (
    !cleanedReference ||
    !cleanedRestaurantId ||
    !cleanedTable ||
    !cleanedName
  ) {
    return res
      .status(400)
      .json({ success: false, error: "Missing payment or order details." });
  }
  if (
    !Number.isFinite(numericTotal) ||
    numericTotal <= 0 ||
    expectedAmount <= 0
  ) {
    return res
      .status(400)
      .json({ success: false, error: "Invalid order total." });
  }
  if (!validateOrderItems(cleanedItems)) {
    return res
      .status(400)
      .json({ success: false, error: "Invalid order items." });
  }

  const calculatedTotal = calculateItemsTotal(cleanedItems);
  if (Math.round(calculatedTotal * 100) !== expectedAmount) {
    return res
      .status(400)
      .json({ success: false, error: "Order total does not match items." });
  }

  try {
    const transaction = await verifyPaystackReference(cleanedReference);
    const metadata = transaction.metadata || {};

    if (Number(transaction.amount) !== expectedAmount) {
      return res.status(400).json({
        success: false,
        error: "Payment amount does not match order total.",
      });
    }
    if (transaction.currency !== "NGN") {
      return res
        .status(400)
        .json({ success: false, error: "Unsupported payment currency." });
    }
    if (
      metadata.restaurantId &&
      metadata.restaurantId !== cleanedRestaurantId
    ) {
      return res
        .status(400)
        .json({ success: false, error: "Payment restaurant mismatch." });
    }
    if (metadata.table && String(metadata.table) !== cleanedTable) {
      return res
        .status(400)
        .json({ success: false, error: "Payment table mismatch." });
    }

    const result = await db.runTransaction(async (tx) => {
      const profileRef = db.doc(
        `restaurants/${cleanedRestaurantId}/profile/info`,
      );
      const paymentRef = db.doc(`paymentReferences/${cleanedReference}`);
      const profileSnap = await tx.get(profileRef);
      const paymentSnap = await tx.get(paymentRef);

      if (!profileSnap.exists) {
        throw Object.assign(new Error("Restaurant not found."), {
          statusCode: 404,
        });
      }

      const profile = profileSnap.data();
      if (normalizePaymentMode(profile.paymentMode) !== "pay_online") {
        throw Object.assign(
          new Error("Online payment is not enabled for this restaurant."),
          { statusCode: 403 },
        );
      }
      if (!profile.paystackSubaccountCode) {
        throw Object.assign(
          new Error("Online payment account is not connected."),
          { statusCode: 400 },
        );
      }

      const transactionSubaccount =
        transaction.subaccount?.subaccount_code ||
        transaction.subaccount_code ||
        null;
      if (
        transactionSubaccount &&
        transactionSubaccount !== profile.paystackSubaccountCode
      ) {
        throw Object.assign(new Error("Payment account mismatch."), {
          statusCode: 400,
        });
      }

      if (paymentSnap.exists && paymentSnap.data().orderId) {
        return {
          orderId: paymentSnap.data().orderId,
          sessionId: paymentSnap.data().sessionId || null,
          reused: true,
        };
      }

      const orderRef = db
        .collection(`restaurants/${cleanedRestaurantId}/orders`)
        .doc();
      let sessionRef;
      let existingOrderIds = [];
      let nextTotalBill = numericTotal;

      if (sessionId) {
        sessionRef = db.doc(
          `restaurants/${cleanedRestaurantId}/tableSessions/${sessionId}`,
        );
        const sessionSnap = await tx.get(sessionRef);
        if (!sessionSnap.exists) {
          throw Object.assign(new Error("Table session not found."), {
            statusCode: 404,
          });
        }
        const session = sessionSnap.data();
        if (String(session.table) !== cleanedTable) {
          throw Object.assign(new Error("Table session mismatch."), {
            statusCode: 400,
          });
        }
        existingOrderIds = Array.isArray(session.orderIds)
          ? session.orderIds
          : [];
        nextTotalBill = Number(session.totalBill || 0) + numericTotal;
      } else {
        sessionRef = db
          .collection(`restaurants/${cleanedRestaurantId}/tableSessions`)
          .doc();
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
          waiterCalledAt: null,
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

// DELETE /delete-user — permanently delete a Firebase Auth account (super admin only)
app.delete("/delete-user", requireFirebaseUser, async (req, res) => {
  if (!(await isSuperAdmin(req.firebaseUser.uid))) {
    return res.status(403).json({ error: "Forbidden" });
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

// ── Staff login (the single shared Orders+QR account for kitchen/cashier) ─────────
// Access collapses to two levels: owner (full) and "staff" (Orders + QR). Individual
// waiters are a name-only roster (restaurants/{id}/staff) — they don't log in.
const genTempPassword = () => {
  const raw = crypto.randomBytes(9).toString("base64").replace(/[^a-zA-Z0-9]/g, "");
  // Always satisfies Firebase's 6-char minimum and mixes letters + a digit.
  return `Srv${raw.slice(0, 8)}7`;
};

const findStaffLogin = async (restaurantId) => {
  const snap = await db
    .collection("users")
    .where("restaurantId", "==", restaurantId)
    .where("role", "==", "staff")
    .limit(1)
    .get();
  return snap.empty ? null : { uid: snap.docs[0].id, ...snap.docs[0].data() };
};

// GET /staff-login?restaurantId= — return the single staff login (without its password).
app.get("/staff-login", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required" });
  if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
  }
  try {
    const staff = await findStaffLogin(restaurantId);
    return res.json({ staff: staff ? { uid: staff.uid, email: staff.email || "" } : null });
  } catch (err) {
    console.error("Get staff login error:", err);
    return res.status(500).json({ error: "Could not load staff login." });
  }
});

// POST /create-staff — create the single staff login with a temporary password (shown once).
app.post(
  "/create-staff",
  rateLimit({ windowMs: 60_000, max: 20 }),
  requireFirebaseUser,
  async (req, res) => {
    const { restaurantId, email } = req.body || {};
    const cleanedRestaurantId = String(restaurantId || "").trim();
    const cleanedEmail = String(email || "").trim().toLowerCase();
    if (!cleanedRestaurantId || !cleanedEmail) {
      return res.status(400).json({ error: "restaurantId and email are required." });
    }
    if (!(await userCanManage(req.firebaseUser.uid, cleanedRestaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant" });
    }
    try {
      if (await findStaffLogin(cleanedRestaurantId)) {
        return res
          .status(409)
          .json({ error: "A staff login already exists. Reset or remove it instead." });
      }
      const tempPassword = genTempPassword();
      const userRecord = await admin.auth().createUser({
        email: cleanedEmail,
        password: tempPassword,
        emailVerified: true, // vouched for by the owner — no separate verification step
      });
      await db.doc(`users/${userRecord.uid}`).set({
        restaurantId: cleanedRestaurantId,
        email: cleanedEmail,
        role: "staff",
        createdAt: FieldValue.serverTimestamp(),
        createdBy: req.firebaseUser.uid,
      });
      return res.json({ success: true, uid: userRecord.uid, email: cleanedEmail, tempPassword });
    } catch (err) {
      if (err.code === "auth/email-already-exists") {
        return res.status(409).json({ error: "That email already has an account." });
      }
      if (err.code === "auth/invalid-email") {
        return res.status(400).json({ error: "That email address is invalid." });
      }
      console.error("Create staff error:", err);
      return res.status(500).json({ error: "Could not create staff login." });
    }
  },
);

// POST /reset-staff-password — issue a fresh temporary password for the staff login.
app.post("/reset-staff-password", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required" });
  if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
  }
  try {
    const staff = await findStaffLogin(restaurantId);
    if (!staff) return res.status(404).json({ error: "No staff login to reset." });
    const tempPassword = genTempPassword();
    await admin.auth().updateUser(staff.uid, { password: tempPassword });
    // Kill any live sessions too (e.g. a stolen tablet) — not just future logins.
    await admin.auth().revokeRefreshTokens(staff.uid).catch(() => {});
    return res.json({ success: true, email: staff.email || "", tempPassword });
  } catch (err) {
    console.error("Reset staff password error:", err);
    return res.status(500).json({ error: "Could not reset password." });
  }
});

// DELETE /delete-staff — remove the staff login (auth account + user doc).
app.delete("/delete-staff", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required" });
  if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
  }
  try {
    const staff = await findStaffLogin(restaurantId);
    if (!staff) return res.status(404).json({ error: "No staff login to remove." });
    await db.doc(`users/${staff.uid}`).delete();
    await admin.auth().deleteUser(staff.uid).catch(() => {});
    return res.json({ success: true });
  } catch (err) {
    console.error("Delete staff error:", err);
    return res.status(500).json({ error: "Could not remove staff login." });
  }
});

// POST /notify-login — new-device login alerts. Each browser sends a stable device ID
// after sign-in; the first-ever device registers silently, any later unknown device is
// registered AND triggers an alert email. Staff-login alerts go to the venue owner.
app.post(
  "/notify-login",
  rateLimit({ windowMs: 60_000, max: 10 }),
  requireFirebaseUser,
  async (req, res) => {
    const deviceId = String(req.body?.deviceId || "").trim().slice(0, 100);
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });

    try {
      const userRef = db.doc(`users/${req.firebaseUser.uid}`);
      const snap = await userRef.get();
      if (!snap.exists) return res.json({ known: true }); // super admin — no user doc

      const userData = snap.data();
      const known = Array.isArray(userData.knownDevices) ? userData.knownDevices : [];
      if (known.includes(deviceId)) return res.json({ known: true });

      await userRef.update({ knownDevices: FieldValue.arrayUnion(deviceId) });

      // First device ever (incl. everyone's next login after this feature ships):
      // register quietly so we don't blast alerts for normal use.
      if (known.length === 0) return res.json({ known: false, first: true });

      // Staff logins alert the owner (they own the credential); others alert themselves.
      let to = req.firebaseUser.email || userData.email || "";
      const isStaff = userData.role === "staff";
      if (isStaff && userData.restaurantId) {
        const profSnap = await db
          .doc(`restaurants/${userData.restaurantId}/profile/info`)
          .get();
        to = profSnap.data()?.email || to;
      }

      if (to) {
        const ua = String(req.headers["user-agent"] || "Unknown device").slice(0, 180);
        const when = new Date().toLocaleString("en-NG", {
          timeZone: "Africa/Lagos",
          dateStyle: "medium",
          timeStyle: "short",
        });
        const acct = isStaff
          ? `the STAFF login (${escapeHtml(userData.email || "")})`
          : "your Servrr account";
        const advice = isStaff
          ? "reset the staff password from your dashboard's Staff tab"
          : 'use "Forgot password" on the login page to reset it';
        await resend.emails.send({
          from: MAIL_FROM,
          to: [to],
          subject: "New sign-in to your Servrr account",
          html: `
            <div style="background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:480px;margin:0 auto;padding:40px 28px;">
              <p style="color:#fa5631;font-size:22px;font-weight:900;letter-spacing:-0.5px;margin:0 0 28px 0;">SERVRR</p>
              <h1 style="color:#fff;font-size:22px;font-weight:800;margin:0 0 12px 0;">New sign-in detected</h1>
              <p style="color:#aaa;font-size:14px;line-height:1.7;margin:0 0 20px 0;">
                A device that hasn't been used before just signed in to ${acct}.
              </p>
              <div style="background:#111;border:1px solid #222;border-radius:14px;padding:18px;margin-bottom:24px;">
                <p style="color:#ccc;font-size:13px;line-height:1.8;margin:0;">
                  <strong style="color:#fff">When:</strong> ${escapeHtml(when)} (Lagos)<br/>
                  <strong style="color:#fff">Device:</strong> ${escapeHtml(ua)}<br/>
                  <strong style="color:#fff">IP:</strong> ${escapeHtml(String(req.ip || "unknown"))}
                </p>
              </div>
              <p style="color:#aaa;font-size:13px;line-height:1.7;margin:0;">
                If this was you or your team, no action is needed. If not, ${advice} immediately —
                that signs the device out.
              </p>
              <p style="color:#333;font-size:11px;text-align:center;margin-top:32px;">© ${new Date().getFullYear()} SERVRR</p>
            </div>`,
        });
      }

      return res.json({ known: false });
    } catch (err) {
      console.error("notify-login error:", err);
      return res.status(500).json({ error: "Could not record login." });
    }
  },
);

// POST /send-receipt — email the full bill to the customer(s) when the table is closed (staff only)
app.post("/send-receipt", rateLimit({ windowMs: 60_000, max: 20 }), requireFirebaseUser, async (req, res) => {
  const { restaurantId, emails, restaurantName, table, orders, totalBill } = req.body;
  const cleanedRestaurantId = String(restaurantId || "").trim();
  if (!cleanedRestaurantId) {
    return res.status(400).json({ error: "restaurantId is required" });
  }
  if (!Array.isArray(emails) || !emails.length) {
    return res.status(400).json({ error: "No email addresses provided" });
  }
  if (!(await userCanOperate(req.firebaseUser.uid, cleanedRestaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
  }

  const safeOrders = Array.isArray(orders) ? orders : [];
  const itemsHtml = safeOrders
    .map((order) => {
      const rows = (order.items || [])
        .map(
          (item) => `
        <tr>
          <td style="padding:6px 0;color:#aaa;font-size:13px;">${Number(item.qty) || 0}× ${escapeHtml(item.name)}</td>
          <td style="padding:6px 0;text-align:right;color:#aaa;font-size:13px;">₦${(parseFloat(item.price) * Number(item.qty) || 0).toLocaleString()}</td>
        </tr>`,
        )
        .join("");
      const header =
        safeOrders.length > 1
          ? `<p style="color:#666;font-size:11px;margin:0 0 8px 0;text-transform:uppercase;letter-spacing:1px;">${escapeHtml(order.customerName)}'s order</p>`
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
      <h1 style="color:#fff;font-size:22px;font-weight:900;margin:0 0 4px 0;">${escapeHtml(restaurantName)}</h1>
      <p style="color:#555;font-size:13px;margin:0 0 32px 0;">Table ${escapeHtml(table)} · Receipt</p>
      <div style="background:#111;border:1px solid #222;padding:20px;margin-bottom:16px;">${itemsHtml}</div>
      <div style="background:#111;border:1px solid #333;padding:16px 20px;display:flex;justify-content:space-between;align-items:center;">
        <span style="color:#666;font-size:14px;text-transform:uppercase;letter-spacing:1px;">Total</span>
        <span style="color:#fff;font-size:22px;font-weight:900;">₦${Number(totalBill).toLocaleString()}</span>
      </div>
      <p style="color:#333;font-size:12px;text-align:center;margin-top:32px;">Thank you for dining with us!</p>
    </div>`;

  try {
    await resend.emails.send({
      from: MAIL_FROM,
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

// Lightweight health check (replaces the old unauthenticated email relay).
app.get("/", (req, res) => res.json({ status: "ok" }));

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
