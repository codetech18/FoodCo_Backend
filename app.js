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

app.use(express.json({
  limit: "25mb",
  verify: (req, _res, buffer) => {
    // Paystack signs the exact request bytes. Keep them before JSON parsing so
    // webhook verification is not affected by whitespace or key ordering.
    const requestPath = String(req.originalUrl || "").split("?")[0].replace(/\/+$/, "");
    if (requestPath === "/paystack-webhook") req.rawBody = buffer;
  },
}));
app.use(express.urlencoded({ limit: "25mb" }));

// Baseline security headers for API responses (the frontend's headers live in vercel.json).
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});

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
  // Diner online payments are paused while SERVRR launches with cash, POS,
  // and bank transfer settlement.
  "at_table";

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

const LEGACY_CHECK_ID = "legacy";
const OPEN_TABLE_SESSION_STATUSES = ["open", "awaiting_payment", "transfer_reported"];
const GROUP_PAYMENT_SHARE_MS = 15 * 60 * 1000;
const validCheckId = (value) => /^c_[a-f0-9]{32}$/.test(String(value || ""));
const validCheckSecret = (value) => /^[a-f0-9]{64}$/.test(String(value || ""));
const hashCheckSecret = (value) => crypto.createHash("sha256").update(value).digest("hex");
const orderCheckId = (order) => order.checkId || LEGACY_CHECK_ID;
const checkState = (session, checkId) => session.checks?.[checkId] || {
  status: checkId === LEGACY_CHECK_ID && !session.checks?.[checkId] &&
    ["awaiting_payment", "transfer_reported", "paid"].includes(session.status)
    ? session.status : "open",
};
const hasValidSessionToken = (session, token) => Boolean(token) &&
  Array.isArray(session.accessTokens) && session.accessTokens.some(
    (entry) => entry.hash === hashSessionAccessToken(token) && Number(entry.expiresAt) > Date.now(),
  );
const hasCheckAccess = (session, checkId, secret) =>
  !session.checks?.[checkId]?.secretHash ||
  (validCheckSecret(secret) && hashCheckSecret(secret) === session.checks[checkId].secretHash);

const createSessionAccessToken = () => crypto.randomBytes(32).toString("hex");
const hashSessionAccessToken = (token) =>
  crypto.createHash("sha256").update(String(token || "")).digest("hex");
const SESSION_IDLE_MS = 4 * 60 * 60 * 1000;
const EMAIL_OTP_TTL_MS = 10 * 60 * 1000;
const EMAIL_OTP_MAX_ATTEMPTS = 5;

const normalizeEmail = (email) => String(email || "").trim().toLowerCase();
const hashValue = (value) =>
  crypto.createHash("sha256").update(String(value || "")).digest("hex");
const otpDocumentId = (purpose, email) => `${purpose}_${hashValue(normalizeEmail(email))}`;
const createOtp = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");

const DEFAULT_MONTHLY_FEES = {
  restaurant: 25000,
  lounge: 40000,
};

const SUBSCRIPTION_PRICING = {
  restaurant: { monthly: 25000, yearly: 250000 },
  lounge: { monthly: 40000, yearly: 400000 },
};

// A venue is operational only after a platform administrator activates it.
// Billing never expires a live venue automatically; suspension is explicit.
const isVenueActive = (profile) => {
  if (!profile) return false;
  return profile.suspended !== true;
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

const paymentRevenueField = (paidVia) =>
  ({
    cash: "cashRevenue",
    pos: "posRevenue",
    transfer: "transferRevenue",
    online: "onlineRevenue",
  })[paidVia] || "otherRevenue";

// Revenue is reported against the venue's operating day, not UTC. Servrr's
// current market is Nigeria, so the reconciliation key follows Lagos time.
const lagosDayKey = (value = new Date()) => {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Lagos",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date(value));
  const values = Object.fromEntries(
    parts.filter((part) => part.type !== "literal").map((part) => [part.type, part.value]),
  );
  return `${values.year}-${values.month}-${values.day}`;
};

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
  if (!profileSnap.exists || profileSnap.data().suspended === true) return false;
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

// Billing must remain available while a workspace is awaiting its first
// payment or recovering from a failed renewal. It therefore checks ownership
// and role without requiring the workspace itself to be active.
const userCanManageSubscription = async (uid, restaurantId) => {
  if (await isSuperAdmin(uid)) return true;
  const profileSnap = await db.doc(`restaurants/${restaurantId}/profile/info`).get();
  if (!profileSnap.exists) return false;
  if (profileSnap.data().ownerUid === uid) return true;
  const userSnap = await db.doc(`users/${uid}`).get();
  if (!userSnap.exists) return false;
  const user = userSnap.data();
  return user.restaurantId === restaurantId && MANAGE_ROLES.includes(user.role);
};

const cloudinaryPublicIdFromUrl = (value) => {
  try {
    const url = new URL(String(value || ""));
    if (!url.hostname.endsWith("res.cloudinary.com")) return "";
    const parts = url.pathname.split("/").filter(Boolean);
    const uploadIndex = parts.indexOf("upload");
    if (uploadIndex < 0) return "";
    const assetParts = parts.slice(uploadIndex + 1);
    while (assetParts[0] && (/^v\d+$/.test(assetParts[0]) || assetParts[0].includes(","))) {
      assetParts.shift();
    }
    return assetParts.join("/").replace(/\.[a-z0-9]+$/i, "");
  } catch {
    return "";
  }
};

const destroyCloudinaryImage = async (publicId) => {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  if (!cloudName || !apiKey || !apiSecret) {
    throw Object.assign(new Error("Cloudinary cleanup is not configured."), { statusCode: 503 });
  }
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = crypto
    .createHash("sha1")
    .update(`public_id=${publicId}&timestamp=${timestamp}${apiSecret}`)
    .digest("hex");
  const form = new URLSearchParams({
    public_id: publicId,
    timestamp: String(timestamp),
    api_key: apiKey,
    signature,
  });
  const response = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/destroy`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || (result.result !== "ok" && result.result !== "not found")) {
    throw new Error(result.error?.message || "Cloudinary asset cleanup failed.");
  }
};

app.post("/delete-restaurant-assets", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim().toLowerCase();
  if (!/^[a-z0-9-]{2,80}$/.test(restaurantId)) {
    return res.status(400).json({ error: "Invalid restaurant ID." });
  }
  if (!(await isSuperAdmin(req.firebaseUser.uid))) {
    return res.status(403).json({ error: "Only a super admin can delete restaurant assets." });
  }

  try {
    const [menuSnap, profileSnap, privateSnap] = await Promise.all([
      db.collection(`restaurants/${restaurantId}/menu`).get(),
      db.doc(`restaurants/${restaurantId}/profile/info`).get(),
      db.doc(`restaurants/${restaurantId}/profile/private`).get(),
    ]);
    const publicIds = new Set();
    for (const snapshot of [profileSnap, privateSnap, ...menuSnap.docs]) {
      if (!snapshot.exists) continue;
      const data = snapshot.data();
      if (data.imagePublicId) publicIds.add(String(data.imagePublicId));
      if (data.logoPublicId) publicIds.add(String(data.logoPublicId));
      const parsedImageId = cloudinaryPublicIdFromUrl(data.imageUrl);
      const parsedLogoId = cloudinaryPublicIdFromUrl(data.logoUrl);
      if (parsedImageId) publicIds.add(parsedImageId);
      if (parsedLogoId) publicIds.add(parsedLogoId);
    }
    for (const publicId of publicIds) await destroyCloudinaryImage(publicId);
    return res.json({ success: true, deleted: publicIds.size });
  } catch (err) {
    console.error("Restaurant asset cleanup error:", err);
    return res.status(err.statusCode || 502).json({
      error: err.message || "Restaurant assets could not be cleaned up.",
    });
  }
});

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

const normalizeSubscriptionType = (value) => value === "lounge" ? "lounge" : "restaurant";
const normalizeSubscriptionCycle = (value) => value === "yearly" ? "yearly" : "monthly";

const getSubscriptionPlanCode = (businessType, billingCycle) => {
  const operation = normalizeSubscriptionType(businessType) === "lounge" ? "LOUNGE" : "RESTAURANT";
  const cycle = normalizeSubscriptionCycle(billingCycle) === "yearly" ? "YEARLY" : "MONTHLY";
  return process.env[`PAYSTACK_${operation}_${cycle}_PLAN_CODE`] || "";
};

const getSubscriptionConfig = (businessType, billingCycle) => {
  const type = normalizeSubscriptionType(businessType);
  const cycle = normalizeSubscriptionCycle(billingCycle);
  return {
    businessType: type,
    billingCycle: cycle,
    planCode: getSubscriptionPlanCode(type, cycle),
    amountNaira: SUBSCRIPTION_PRICING[type][cycle],
  };
};

const planCodeFromPayload = (data) =>
  data?.plan?.plan_code ||
  data?.plan_object?.plan_code ||
  data?.subscription?.plan?.plan_code ||
  data?.metadata?.planCode ||
  "";

const subscriptionCodeFromPayload = (data) =>
  data?.subscription_code || data?.subscription?.subscription_code || "";

const customerCodeFromPayload = (data) =>
  data?.customer?.customer_code || data?.customer_code || "";

const subscriptionIntentId = (email, planCode) =>
  hashValue(`${normalizeEmail(email)}|${String(planCode || "")}`);

const customerPlanId = (customerCode, planCode) =>
  hashValue(`${String(customerCode || "")}|${String(planCode || "")}`);

const addSubscriptionPeriod = (value, cycle) => {
  const next = new Date(value);
  if (normalizeSubscriptionCycle(cycle) === "yearly") {
    next.setUTCFullYear(next.getUTCFullYear() + 1);
  } else {
    // Paystack renews subscriptions opened on the 29th–31st on the 28th.
    const originalDay = next.getUTCDate();
    next.setUTCDate(1);
    next.setUTCMonth(next.getUTCMonth() + 1);
    next.setUTCDate(Math.min(originalDay, 28));
  }
  return next;
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

const sendOtpEmail = async ({ email, code, purpose }) => {
  const heading = purpose === "password_reset" ? "Reset your password" : "Verify your email";
  const detail = purpose === "password_reset"
    ? "Use this code to choose a new Servrr password."
    : "Use this code to continue setting up your Servrr workspace.";
  const html = `
    <div style="background:#fffaf5;font-family:Georgia,'Times New Roman',serif;max-width:480px;margin:0 auto;padding:40px 28px;color:#191511;">
      <p style="color:#f76b00;font-size:28px;font-weight:700;margin:0 0 32px;">Servrr</p>
      <h1 style="font-size:28px;line-height:1.15;margin:0 0 12px;">${heading}</h1>
      <p style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#685f57;font-size:14px;line-height:1.6;margin:0 0 24px;">${detail}</p>
      <div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:10px;color:#191511;font-size:30px;font-weight:800;background:#fff;border:1px solid #f0ded0;border-radius:14px;padding:18px 20px;text-align:center;">${code}</div>
      <p style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#8a8179;font-size:12px;line-height:1.6;margin:24px 0 0;">This code expires in 10 minutes. If you did not request it, you can ignore this email.</p>
    </div>`;
  await resend.emails.send({
    from: MAIL_FROM,
    to: [email],
    subject: `${code} is your Servrr verification code`,
    html,
  });
};

// ── Public setup and email verification ──────────────────────────────────────
// Signup is intentionally verified before Firebase Auth creates an account. This
// avoids abandoned/unverified users and binds the verified email to the invite.
app.post("/setup-requests", rateLimit({ windowMs: 15 * 60_000, max: 10 }), async (req, res) => {
  const name = String(req.body?.name || "").trim().slice(0, 120);
  const businessName = String(req.body?.businessName || "").trim().slice(0, 160);
  const email = normalizeEmail(req.body?.email);
  const phone = String(req.body?.phone || "").trim().slice(0, 40);
  const operatingMode = req.body?.operatingMode === "lounge" ? "lounge" : "restaurant";
  const planKind = req.body?.planKind === "custom" ? "custom" : "standard";
  const needs = String(req.body?.needs || "").trim().slice(0, 1500);
  if (!name || !businessName || !email || !phone) {
    return res.status(400).json({ error: "Name, business name, email, and phone are required." });
  }
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }

  try {
    const ref = await db.collection("setupRequests").add({
      name,
      businessName,
      email,
      phone,
      operatingMode,
      planKind,
      needs,
      status: "new",
      createdAt: FieldValue.serverTimestamp(),
      reviewedAt: null,
      reviewedByUid: null,
      inviteCodeId: null,
    });
    return res.status(201).json({ success: true, requestId: ref.id });
  } catch (err) {
    console.error("Setup request error:", err);
    return res.status(500).json({ error: "Could not submit your setup request." });
  }
});

app.post("/auth/request-otp", rateLimit({ windowMs: 15 * 60_000, max: 10 }), async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const purpose = req.body?.purpose === "password_reset" ? "password_reset" : "signup";
  const inviteCode = String(req.body?.inviteCode || "").trim().toUpperCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }
  if (purpose === "signup" && !inviteCode) {
    return res.status(400).json({ error: "An invite code is required." });
  }

  try {
    if (purpose === "signup") {
      const inviteSnap = await db.collection("inviteCodes")
        .where("code", "==", inviteCode)
        .where("status", "==", "unused")
        .limit(1)
        .get();
      if (inviteSnap.empty || isExpiredTimestamp(inviteSnap.docs[0].data().expiresAt)) {
        return res.status(400).json({ error: "That invite code is invalid or has expired." });
      }
    } else {
      // Keep the response generic so this endpoint cannot be used to enumerate accounts.
      try {
        await admin.auth().getUserByEmail(email);
      } catch (_) {
        return res.json({ success: true, expiresInSeconds: EMAIL_OTP_TTL_MS / 1000 });
      }
    }

    const code = createOtp();
    const now = Date.now();
    await db.doc(`emailOtps/${otpDocumentId(purpose, email)}`).set({
      purpose,
      emailHash: hashValue(email),
      codeHash: hashValue(`${purpose}:${email}:${code}`),
      inviteCode: purpose === "signup" ? inviteCode : null,
      attempts: 0,
      expiresAt: new Date(now + EMAIL_OTP_TTL_MS),
      createdAt: FieldValue.serverTimestamp(),
      verifiedAt: null,
      verificationTokenHash: null,
    });
    await sendOtpEmail({ email, code, purpose });
    return res.json({ success: true, expiresInSeconds: EMAIL_OTP_TTL_MS / 1000 });
  } catch (err) {
    console.error("OTP request error:", err);
    return res.status(500).json({ error: "Could not send a verification code. Please try again." });
  }
});

app.post("/auth/verify-otp", rateLimit({ windowMs: 15 * 60_000, max: 20 }), async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const purpose = req.body?.purpose === "password_reset" ? "password_reset" : "signup";
  const code = String(req.body?.code || "").replace(/\D/g, "");
  if (!/^\S+@\S+\.\S+$/.test(email) || code.length !== 6) {
    return res.status(400).json({ error: "Enter the six-digit code from your email." });
  }

  try {
    const otpRef = db.doc(`emailOtps/${otpDocumentId(purpose, email)}`);
    const verificationToken = crypto.randomBytes(32).toString("hex");
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(otpRef);
      const record = snap.exists ? snap.data() : null;
      if (!record || isExpiredTimestamp(record.expiresAt)) {
        throw Object.assign(new Error("That code has expired. Request a new one."), { statusCode: 400 });
      }
      if (Number(record.attempts || 0) >= EMAIL_OTP_MAX_ATTEMPTS) {
        throw Object.assign(new Error("Too many incorrect attempts. Request a new code."), { statusCode: 429 });
      }
      if (record.codeHash !== hashValue(`${purpose}:${email}:${code}`)) {
        tx.update(otpRef, { attempts: FieldValue.increment(1) });
        throw Object.assign(new Error("That code is incorrect."), { statusCode: 400 });
      }
      tx.update(otpRef, {
        codeHash: null,
        attempts: FieldValue.increment(1),
        verifiedAt: FieldValue.serverTimestamp(),
        verificationTokenHash: hashValue(verificationToken),
        verificationExpiresAt: new Date(Date.now() + EMAIL_OTP_TTL_MS),
      });
    });
    return res.json({ success: true, verificationToken });
  } catch (err) {
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not verify that code." });
  }
});

app.post("/auth/reset-password", rateLimit({ windowMs: 15 * 60_000, max: 10 }), async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const verificationToken = String(req.body?.verificationToken || "");
  const password = String(req.body?.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email) || !verificationToken || password.length < 8) {
    return res.status(400).json({ error: "Use a verified code and a password with at least 8 characters." });
  }
  try {
    const otpRef = db.doc(`emailOtps/${otpDocumentId("password_reset", email)}`);
    const otpSnap = await otpRef.get();
    const otp = otpSnap.exists ? otpSnap.data() : null;
    if (!otp || otp.verificationTokenHash !== hashValue(verificationToken) || isExpiredTimestamp(otp.verificationExpiresAt)) {
      return res.status(403).json({ error: "Verify a new email code before resetting your password." });
    }
    const user = await admin.auth().getUserByEmail(email);
    await admin.auth().updateUser(user.uid, { password });
    await admin.auth().revokeRefreshTokens(user.uid);
    await otpRef.update({ verificationTokenHash: null, usedAt: FieldValue.serverTimestamp() });
    return res.json({ success: true });
  } catch (err) {
    console.error("Password reset error:", err);
    return res.status(500).json({ error: "Could not reset your password. Please try again." });
  }
});

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
    logoPublicId,
    address,
    phone,
    contactEmail,
    instagram,
    twitter,
    verificationToken,
  } = req.body || {};

  const email = req.firebaseUser.email;
  const uid = req.firebaseUser.uid;
  const restaurantId = slugify(name);
  const selectedPaymentMode = normalizePaymentMode(paymentMode);
  const requestedBusinessType = businessType === "lounge" ? "lounge" : "restaurant";
  // Firestore rejects undefined values. Optional profile details are persisted as
  // empty strings until the venue adds them in Settings.
  const profileAddress = typeof address === "string" ? address.trim() : "";
  const profilePhone = typeof phone === "string" ? phone.trim() : "";
  const profileContactEmail = typeof contactEmail === "string" && contactEmail.trim()
    ? contactEmail.trim().toLowerCase()
    : email;
  const profileInstagram = typeof instagram === "string" ? instagram.trim() : "";
  const profileTwitter = typeof twitter === "string" ? twitter.trim() : "";
  const profileLogoUrl = typeof logoUrl === "string" ? logoUrl.trim() : "";
  const profileLogoPublicId = typeof logoPublicId === "string" ? logoPublicId.trim() : "";

  if (!inviteCode || !name || !restaurantId || !email) {
    return res
      .status(400)
      .json({ error: "Invite code, restaurant name, and email are required." });
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

      const otpRef = db.doc(`emailOtps/${otpDocumentId("signup", email)}`);
      const [userSnap, profileSnap, inviteSnap, otpSnap] = await Promise.all([
        tx.get(userRef),
        tx.get(profileRef),
        tx.get(inviteQuery),
        tx.get(otpRef),
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

      const otp = otpSnap.exists ? otpSnap.data() : null;
      if (
        !verificationToken ||
        !otp ||
        otp.inviteCode !== String(inviteCode).trim().toUpperCase() ||
        otp.verificationTokenHash !== hashValue(verificationToken) ||
        isExpiredTimestamp(otp.verificationExpiresAt)
      ) {
        throw Object.assign(new Error("Verify your email before completing signup."), { statusCode: 403 });
      }

      const inviteDoc = inviteSnap.docs[0];
      const inviteData = inviteDoc.data();
      if (isExpiredTimestamp(inviteData.expiresAt)) {
        throw Object.assign(new Error("This invite code has expired."), {
          statusCode: 400,
        });
      }

      // Operational mode and commercial terms come from the approved invite,
      // not from browser-submitted signup data.
      const selectedBusinessType = inviteData.operatingMode === "lounge"
        ? "lounge"
        : requestedBusinessType;
      const planKind = inviteData.planKind === "custom" ? "custom" : "standard";
      const customMonthlyFee = Number(inviteData.monthlyFee);
      const monthlyFee = planKind === "custom" && Number.isFinite(customMonthlyFee) && customMonthlyFee > 0
        ? customMonthlyFee
        : DEFAULT_MONTHLY_FEES[selectedBusinessType];

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
        planKind,
        monthlyFee,
        accentColor: accentColor || "#fa5631",
        tagline: tagline || "",
        description: description || "",
        logoUrl: profileLogoUrl,
        logoPublicId: profileLogoPublicId,
        address: profileAddress,
        phone: profilePhone,
        contactEmail: profileContactEmail,
        instagram: profileInstagram,
        twitter: profileTwitter,
        paymentPreference: selectedPaymentMode,
        paymentMode: selectedPaymentMode,
        paymentModeUpdatedAt: FieldValue.serverTimestamp(),
        subscriptionStatus: "payment_pending",
        suspended: true,
        suspendedReason: "payment_pending",
        createdAt: FieldValue.serverTimestamp(),
      });

      tx.update(inviteDoc.ref, {
        status: "used",
        usedBy: restaurantId,
        usedByUid: uid,
        usedAt: FieldValue.serverTimestamp(),
      });
      tx.update(otpRef, {
        verificationTokenHash: null,
        usedAt: FieldValue.serverTimestamp(),
      });

      return { restaurantId };
    });

    // The OTP proves control of this email, so mark the Firebase account verified.
    await admin.auth().updateUser(uid, { emailVerified: true });

    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Complete signup error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Signup setup failed. Please try again.",
    });
  }
});

// POST /restore-restaurant-profile — recover the minimal profile document when
// a venue's parent/profile document was accidentally removed in Firestore.
// This intentionally does not recreate menu items, orders, or other deleted data.
app.post(
  "/restore-restaurant-profile",
  rateLimit({ windowMs: 15 * 60_000, max: 10 }),
  requireFirebaseUser,
  async (req, res) => {
    const restaurantId = String(req.body?.restaurantId || "")
      .trim()
      .toLowerCase();
    const requestedName = String(req.body?.name || "").trim().slice(0, 100);

    if (!/^[a-z0-9-]{2,80}$/.test(restaurantId)) {
      return res.status(400).json({ error: "Enter a valid workspace ID." });
    }

    try {
      const uid = req.firebaseUser.uid;
      const superAdmin = await isSuperAdmin(uid);
      const result = await db.runTransaction(async (tx) => {
        const userRef = db.doc(`users/${uid}`);
        const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
        const restaurantRef = db.doc(`restaurants/${restaurantId}`);
        const [userSnap, profileSnap] = await Promise.all([
          tx.get(userRef),
          tx.get(profileRef),
        ]);

        if (!userSnap.exists) {
          throw Object.assign(new Error("Your owner account record could not be found."), {
            statusCode: 404,
          });
        }

        const userData = userSnap.data();
        const ownerCanRecover =
          userData.restaurantId === restaurantId &&
          (!userData.role || userData.role === "owner");
        if (!superAdmin && !ownerCanRecover) {
          throw Object.assign(
            new Error("Only the original owner can recover this workspace."),
            { statusCode: 403 },
          );
        }

        if (profileSnap.exists) {
          return { restored: false, restaurantId };
        }

        const name = requestedName || userData.restaurantName || restaurantId;
        const email = userData.email || req.firebaseUser.email || "";

        // Keep this profile deliberately minimal. Recovered workspaces remain active
        // unless a platform administrator explicitly suspends them.
        tx.set(profileRef, {
          restaurantId,
          ownerUid: uid,
          name,
          email,
          contactEmail: email,
          accentColor: "#fa5631",
          paymentMode: "at_table",
          paymentPreference: "at_table",
          suspended: false,
          recoveredAt: FieldValue.serverTimestamp(),
          recoveryVersion: 1,
        });
        tx.set(
          restaurantRef,
          {
            restoredParent: true,
            restoredAt: FieldValue.serverTimestamp(),
          },
          { merge: true },
        );

        // Older owner records may not contain a role, which would otherwise
        // make Firestore rules reject every dashboard query after recovery.
        if (!userData.role) {
          tx.set(userRef, { role: "owner" }, { merge: true });
        }

        return { restored: true, restaurantId };
      });

      return res.json({ success: true, ...result });
    } catch (err) {
      console.error("Restaurant profile recovery error:", err);
      return res.status(err.statusCode || 500).json({
        error: err.message || "The workspace profile could not be restored.",
      });
    }
  },
);

// POST /restore-legacy-workspace-data — copies the original single-tenant
// root collections into the current restaurant-scoped paths. The source data
// is intentionally retained and existing destination documents are skipped,
// making the operation safe to retry after a partial migration.
app.post(
  "/restore-legacy-workspace-data",
  rateLimit({ windowMs: 15 * 60_000, max: 5 }),
  requireFirebaseUser,
  async (req, res) => {
    const restaurantId = String(req.body?.restaurantId || "")
      .trim()
      .toLowerCase();

    if (!/^[a-z0-9-]{2,80}$/.test(restaurantId)) {
      return res.status(400).json({ error: "Enter a valid workspace ID." });
    }

    try {
      const uid = req.firebaseUser.uid;
      const [superAdmin, userSnap, profileSnap] = await Promise.all([
        isSuperAdmin(uid),
        db.doc(`users/${uid}`).get(),
        db.doc(`restaurants/${restaurantId}/profile/info`).get(),
      ]);
      const userData = userSnap.exists ? userSnap.data() : {};
      const profileData = profileSnap.exists ? profileSnap.data() : {};
      const isOriginalOwner =
        userData.restaurantId === restaurantId &&
        (userData.role === "owner" || !userData.role) &&
        (!profileData.ownerUid || profileData.ownerUid === uid);

      if (!superAdmin && !isOriginalOwner) {
        return res.status(403).json({ error: "Only the workspace owner can recover this data." });
      }
      if (!profileSnap.exists) {
        return res.status(409).json({ error: "Restore the workspace profile before recovering its data." });
      }

      // Deleting a Firestore parent document does not delete its subcollections.
      // Scan those subcollections as well as the original root collections so
      // data from an older restaurant ID can be recovered after the profile is
      // recreated.
      const [legacyMenu, legacyOrders, allMenu, allOrders, profiles, currentMenu, currentOrders] =
        await Promise.all([
          db.collection("menu").get(),
          db.collection("orders").get(),
          db.collectionGroup("menu").get(),
          db.collectionGroup("orders").get(),
          db.collectionGroup("profile").get(),
          db.collection(`restaurants/${restaurantId}/menu`).get(),
          db.collection(`restaurants/${restaurantId}/orders`).get(),
        ]);

      const relatedRestaurantIds = new Set([restaurantId]);
      const normalizedUserEmail = String(req.firebaseUser.email || "").trim().toLowerCase();
      for (const profile of profiles.docs) {
        const data = profile.data() || {};
        const profileEmail = String(data.email || data.contactEmail || "").trim().toLowerCase();
        if (data.ownerUid === uid || (normalizedUserEmail && profileEmail === normalizedUserEmail)) {
          const parts = profile.ref.path.split("/");
          if (parts[0] === "restaurants" && parts[2] === "profile") {
            relatedRestaurantIds.add(parts[1]);
          }
        }
      }

      const sourceRecords = (rootSnapshot, groupSnapshot, collectionName) => {
        const records = new Map();
        for (const snapshot of rootSnapshot.docs) {
          records.set(`${collectionName}/${snapshot.id}`, snapshot);
        }
        for (const snapshot of groupSnapshot.docs) {
          const parts = snapshot.ref.path.split("/");
          const sourceRestaurantId = parts[0] === "restaurants" ? parts[1] : null;
          if (
            sourceRestaurantId &&
            parts[2] === collectionName &&
            (relatedRestaurantIds.has(sourceRestaurantId) || snapshot.data()?.restaurantId === restaurantId)
          ) {
            records.set(snapshot.ref.path, snapshot);
          }
        }
        return [...records.values()];
      };

      const legacyMenuRecords = sourceRecords(legacyMenu, allMenu, "menu");
      const legacyOrderRecords = sourceRecords(legacyOrders, allOrders, "orders");
      if (legacyMenuRecords.length === 0 && legacyOrderRecords.length === 0) {
        return res.status(404).json({ error: "No legacy menu or transaction records were found." });
      }

      const currentMenuIds = new Set(currentMenu.docs.map((snapshot) => snapshot.id));
      const currentOrderIds = new Set(currentOrders.docs.map((snapshot) => snapshot.id));
      const pendingWrites = [];

      for (const snapshot of legacyMenuRecords) {
        if (currentMenuIds.has(snapshot.id)) continue;
        pendingWrites.push({
          ref: db.doc(`restaurants/${restaurantId}/menu/${snapshot.id}`),
          data: snapshot.data(),
          type: "menu",
        });
      }
      for (const snapshot of legacyOrderRecords) {
        if (currentOrderIds.has(snapshot.id)) continue;
        pendingWrites.push({
          ref: db.doc(`restaurants/${restaurantId}/orders/${snapshot.id}`),
          data: snapshot.data(),
          type: "orders",
        });
      }

      let menuCopied = 0;
      let ordersCopied = 0;
      for (let offset = 0; offset < pendingWrites.length; offset += 400) {
        const batch = db.batch();
        const chunk = pendingWrites.slice(offset, offset + 400);
        for (const write of chunk) {
          batch.set(write.ref, write.data);
          if (write.type === "menu") menuCopied += 1;
          if (write.type === "orders") ordersCopied += 1;
        }
        await batch.commit();
      }

      await db.doc(`restaurants/${restaurantId}/profile/info`).set(
        {
          legacyDataRecoveredAt: FieldValue.serverTimestamp(),
          legacyMenuRecovered: legacyMenuRecords.length,
          legacyOrdersRecovered: legacyOrderRecords.length,
        },
        { merge: true },
      );

      return res.json({
        success: true,
        restaurantId,
        menuCopied,
        ordersCopied,
        menuFound: legacyMenuRecords.length,
        ordersFound: legacyOrderRecords.length,
        menuAlreadyPresent: currentMenu.size,
        ordersAlreadyPresent: currentOrders.size,
      });
    } catch (err) {
      console.error("Legacy workspace data recovery error:", err);
      return res.status(500).json({
        error: "The existing menu and transactions could not be recovered right now.",
      });
    }
  },
);

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

// POST /subscription-checkout — creates the first Paystack charge for a Servrr
// subscription. The attached Paystack plan creates subsequent automatic renewals.
app.post("/subscription-checkout", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const requestedCycle = normalizeSubscriptionCycle(req.body?.billingCycle);
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required." });
  try {
    if (!(await userCanManageSubscription(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant." });
    }
    const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
    const profileSnap = await profileRef.get();
    if (!profileSnap.exists) return res.status(404).json({ error: "Restaurant profile not found." });
    const profile = profileSnap.data();
    if (profile.planKind === "custom") {
      return res.status(409).json({ error: "Your Custom plan is activated by the Servrr team. Please contact support." });
    }
    if (profile.paystackSubscriptionCode && ["active", "non_renewing"].includes(profile.subscriptionStatus)) {
      return res.status(409).json({ error: "Automatic billing is already active. Use Manage billing to update or cancel it." });
    }
    if (profile.pendingSubscriptionReference && profile.pendingSubscriptionCycle === requestedCycle) {
      const pendingSnap = await db.doc(`subscriptionCheckouts/${profile.pendingSubscriptionReference}`).get();
      const pending = pendingSnap.data();
      if (pendingSnap.exists && pending?.status === "initialized" && pending?.authorizationUrl) {
        return res.json({
          authorizationUrl: pending.authorizationUrl,
          reference: profile.pendingSubscriptionReference,
        });
      }
    }
    const config = getSubscriptionConfig(profile.businessType, requestedCycle);
    if (!config.planCode) {
      return res.status(503).json({ error: "Subscription billing is not configured yet. Please contact support." });
    }
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(503).json({ error: "Subscription billing is not configured yet. Please contact support." });
    }
    const billingEmail = normalizeEmail(req.firebaseUser.email || profile.email);
    if (!billingEmail) return res.status(400).json({ error: "A billing email is required." });
    const response = await fetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: billingEmail,
        amount: config.amountNaira * 100,
        plan: config.planCode,
        callback_url: `${APP_URL}/${encodeURIComponent(restaurantId)}/admin?subscription=complete`,
        metadata: {
          restaurantId,
          purpose: "servrr_subscription",
          businessType: config.businessType,
          billingCycle: config.billingCycle,
          planCode: config.planCode,
        },
      }),
    });
    const payload = await response.json();
    const checkoutReference = payload.data?.reference;
    if (!response.ok || !payload.status || !payload.data?.authorization_url || !checkoutReference) {
      return res.status(502).json({ error: payload.message || "Could not start subscription checkout." });
    }
    const checkout = {
      reference: checkoutReference,
      restaurantId,
      billingEmail,
      businessType: config.businessType,
      billingCycle: config.billingCycle,
      planCode: config.planCode,
      amountNaira: config.amountNaira,
      amountKobo: config.amountNaira * 100,
      authorizationUrl: payload.data.authorization_url,
      accessCode: payload.data.access_code || null,
      status: "initialized",
      createdAt: FieldValue.serverTimestamp(),
    };
    const batch = db.batch();
    batch.set(db.doc(`subscriptionCheckouts/${checkoutReference}`), checkout);
    batch.set(
      db.doc(`subscriptionIntents/${subscriptionIntentId(billingEmail, config.planCode)}`),
      checkout,
      { merge: true },
    );
    batch.set(profileRef, {
      pendingSubscriptionReference: checkoutReference,
      pendingSubscriptionCycle: config.billingCycle,
      pendingSubscriptionPlanCode: config.planCode,
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });
    await batch.commit();
    return res.json({
      authorizationUrl: payload.data.authorization_url,
      reference: checkoutReference,
    });
  } catch (err) {
    console.error("Subscription checkout error:", err);
    return res.status(500).json({ error: "Could not start subscription checkout." });
  }
});

app.post("/subscription-manage-link", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required." });
  try {
    if (!(await userCanManageSubscription(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant." });
    }
    const profileSnap = await db.doc(`restaurants/${restaurantId}/profile/info`).get();
    const subscriptionCode = profileSnap.data()?.paystackSubscriptionCode;
    if (!subscriptionCode) {
      return res.status(404).json({ error: "No automatic subscription is connected yet." });
    }
    const response = await fetch(
      `https://api.paystack.co/subscription/${encodeURIComponent(subscriptionCode)}/manage/link`,
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } },
    );
    const payload = await response.json();
    if (!response.ok || !payload.status || !payload.data?.link) {
      return res.status(502).json({ error: payload.message || "Could not open subscription management." });
    }
    return res.json({ url: payload.data.link });
  } catch (err) {
    console.error("Subscription management link error:", err);
    return res.status(500).json({ error: "Could not open subscription management." });
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

const resolveSubscriptionContext = async (data, reference) => {
  const planCode = planCodeFromPayload(data);
  const subscriptionCode = subscriptionCodeFromPayload(data);
  const customerCode = customerCodeFromPayload(data);

  if (reference) {
    const checkoutSnap = await db.doc(`subscriptionCheckouts/${reference}`).get();
    if (checkoutSnap.exists) return { ...checkoutSnap.data(), subscriptionCode, customerCode };
  }
  if (subscriptionCode) {
    const subscriptionSnap = await db.doc(`paystackSubscriptions/${subscriptionCode}`).get();
    if (subscriptionSnap.exists) return { ...subscriptionSnap.data(), subscriptionCode, customerCode, planCode: planCode || subscriptionSnap.data().planCode };
  }
  if (customerCode && planCode) {
    const customerPlanSnap = await db.doc(`paystackCustomerPlans/${customerPlanId(customerCode, planCode)}`).get();
    if (customerPlanSnap.exists) return { ...customerPlanSnap.data(), subscriptionCode, customerCode, planCode };
  }
  const customerEmail = normalizeEmail(data?.customer?.email);
  if (customerEmail && planCode) {
    const intentSnap = await db.doc(`subscriptionIntents/${subscriptionIntentId(customerEmail, planCode)}`).get();
    if (intentSnap.exists) return { ...intentSnap.data(), subscriptionCode, customerCode, planCode };
  }
  return null;
};

const recordSuccessfulSubscriptionPayment = async (data, eventName) => {
  const transaction = data?.transaction && typeof data.transaction === "object"
    ? data.transaction
    : data;
  const reference = String(transaction?.reference || data?.reference || "").trim();
  if (!reference) return false;

  const context = await resolveSubscriptionContext(data, reference) ||
    await resolveSubscriptionContext(transaction, reference);
  if (!context?.restaurantId) return false;

  const config = getSubscriptionConfig(context.businessType, context.billingCycle);
  const receivedPlanCode = planCodeFromPayload(data) || planCodeFromPayload(transaction) || context.planCode;
  const amountKobo = Number(transaction?.amount ?? data?.amount);
  const currency = String(transaction?.currency || data?.currency || "NGN").toUpperCase();
  if (!config.planCode || receivedPlanCode !== config.planCode) {
    throw new Error(`Subscription plan mismatch for ${context.restaurantId}.`);
  }
  if (currency !== "NGN" || amountKobo !== config.amountNaira * 100) {
    throw new Error(`Subscription amount mismatch for ${context.restaurantId}.`);
  }

  const profileRef = db.doc(`restaurants/${context.restaurantId}/profile/info`);
  const processedRef = db.doc(`subscriptionPayments/${hashValue(reference)}`);
  const billingRef = db.doc(`restaurants/${context.restaurantId}/billing/${hashValue(reference)}`);
  const subscriptionCode = subscriptionCodeFromPayload(data) || context.subscriptionCode || "";
  const customerCode = customerCodeFromPayload(data) || customerCodeFromPayload(transaction) || context.customerCode || "";
  const nextPaymentValue = data?.subscription?.next_payment_date || data?.next_payment_date;

  await db.runTransaction(async (tx) => {
    const [processedSnap, profileSnap] = await Promise.all([
      tx.get(processedRef),
      tx.get(profileRef),
    ]);
    if (processedSnap.exists) return;
    if (!profileSnap.exists) throw new Error(`Workspace ${context.restaurantId} not found.`);

    const profile = profileSnap.data();
    const now = new Date();
    const currentUntil = profile.subscriptionPaidUntil?.toDate?.() || null;
    const base = currentUntil && currentUntil > now ? currentUntil : now;
    const eventNextPayment = nextPaymentValue ? new Date(nextPaymentValue) : null;
    const paidUntil = eventNextPayment && Number.isFinite(eventNextPayment.getTime()) && eventNextPayment > now
      ? eventNextPayment
      : addSubscriptionPeriod(base, config.billingCycle);
    const clearsBillingSuspension = !profile.suspended || [
      "payment_pending",
      "subscription_failed",
      "subscription_lapsed",
    ].includes(profile.suspendedReason);

    tx.set(profileRef, {
      businessType: config.businessType,
      billingCycle: config.billingCycle,
      monthlyFee: SUBSCRIPTION_PRICING[config.businessType].monthly,
      billingAmountPaid: config.amountNaira,
      subscriptionStatus: "active",
      subscriptionPaidUntil: paidUntil,
      subscriptionAutoRenew: true,
      subscriptionPlanCode: config.planCode,
      paystackSubscriptionCode: subscriptionCode || profile.paystackSubscriptionCode || null,
      paystackCustomerCode: customerCode || profile.paystackCustomerCode || null,
      lastSubscriptionPaymentAt: FieldValue.serverTimestamp(),
      lastSubscriptionReference: reference,
      pendingSubscriptionReference: FieldValue.delete(),
      pendingSubscriptionCycle: FieldValue.delete(),
      pendingSubscriptionPlanCode: FieldValue.delete(),
      ...(clearsBillingSuspension ? { suspended: false, suspendedReason: null } : {}),
    }, { merge: true });
    tx.set(billingRef, {
      date: FieldValue.serverTimestamp(),
      type: config.businessType,
      planKind: profile.planKind || "standard",
      cycle: config.billingCycle,
      amount: config.amountNaira,
      status: "paid",
      reference,
      source: "paystack_subscription",
      event: eventName,
    });
    tx.set(processedRef, {
      reference,
      restaurantId: context.restaurantId,
      planCode: config.planCode,
      amountKobo,
      event: eventName,
      processedAt: FieldValue.serverTimestamp(),
    });
    if (subscriptionCode) {
      tx.set(db.doc(`paystackSubscriptions/${subscriptionCode}`), {
        restaurantId: context.restaurantId,
        businessType: config.businessType,
        billingCycle: config.billingCycle,
        planCode: config.planCode,
        customerCode: customerCode || null,
        subscriptionCode,
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
    }
    if (customerCode) {
      tx.set(db.doc(`paystackCustomerPlans/${customerPlanId(customerCode, config.planCode)}`), {
        restaurantId: context.restaurantId,
        businessType: config.businessType,
        billingCycle: config.billingCycle,
        planCode: config.planCode,
        customerCode,
        subscriptionCode: subscriptionCode || null,
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
    }
  });

  await db.doc(`subscriptionCheckouts/${reference}`).set({
    status: "paid",
    paidAt: FieldValue.serverTimestamp(),
  }, { merge: true });
  return true;
};

app.post("/paystack-webhook", async (req, res) => {
  const signature = String(req.headers["x-paystack-signature"] || "");
  const secret = process.env.PAYSTACK_SECRET_KEY || "";
  const hash = crypto.createHmac("sha512", secret).update(req.rawBody || Buffer.from("")).digest("hex");
  const signatureMatches = signature.length === hash.length &&
    crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(hash));
  if (!secret || !signatureMatches) return res.status(401).send("Invalid signature");

  const event = req.body || {};
  const data = event.data || {};
  const eventName = String(event.event || "");
  const transaction = data?.transaction && typeof data.transaction === "object" ? data.transaction : data;
  const reference = String(transaction?.reference || data?.reference || "").trim();

  try {
    if (eventName === "charge.success") {
      await recordSuccessfulSubscriptionPayment(data, eventName);
    }

    if (eventName === "invoice.update" && data.paid === true && data.status === "success") {
      await recordSuccessfulSubscriptionPayment(data, eventName);
    }

    if (eventName === "subscription.create") {
      const context = await resolveSubscriptionContext(data, reference);
      const subscriptionCode = subscriptionCodeFromPayload(data);
      const planCode = planCodeFromPayload(data) || context?.planCode;
      const customerCode = customerCodeFromPayload(data) || context?.customerCode;
      if (context?.restaurantId && subscriptionCode && planCode) {
        const businessType = normalizeSubscriptionType(context.businessType);
        const billingCycle = normalizeSubscriptionCycle(context.billingCycle);
        const batch = db.batch();
        batch.set(db.doc(`paystackSubscriptions/${subscriptionCode}`), {
          restaurantId: context.restaurantId,
          businessType,
          billingCycle,
          subscriptionCode,
          planCode,
          customerCode: customerCode || null,
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
        batch.set(db.doc(`restaurants/${context.restaurantId}/profile/info`), {
          paystackSubscriptionCode: subscriptionCode,
          paystackCustomerCode: customerCode || null,
          subscriptionPlanCode: planCode,
          subscriptionAutoRenew: true,
          subscriptionStatus: "active",
          subscriptionNextPaymentAt: data.next_payment_date ? new Date(data.next_payment_date) : null,
        }, { merge: true });
        if (customerCode) {
          batch.set(db.doc(`paystackCustomerPlans/${customerPlanId(customerCode, planCode)}`), {
            restaurantId: context.restaurantId,
            businessType,
            billingCycle,
            subscriptionCode,
            planCode,
            customerCode,
            updatedAt: FieldValue.serverTimestamp(),
          }, { merge: true });
        }
        await batch.commit();
      }
    }

    if (["subscription.not_renew", "subscription.disable", "invoice.payment_failed"].includes(eventName)) {
      const context = await resolveSubscriptionContext(data, reference);
      if (context?.restaurantId) {
        const status = eventName === "invoice.payment_failed"
          ? "past_due"
          : eventName === "subscription.not_renew" ? "non_renewing" : "cancelled";
        await db.doc(`restaurants/${context.restaurantId}/profile/info`).set({
          subscriptionStatus: status,
          subscriptionAutoRenew: eventName === "invoice.payment_failed",
          subscriptionPaymentFailedAt: eventName === "invoice.payment_failed" ? FieldValue.serverTimestamp() : null,
          subscriptionUpdatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      }
    }

    if (reference) {
      const metadata = transaction.metadata || data.metadata || {};
      await db.doc(`paymentReferences/${reference}`).set({
        reference,
        event: eventName || null,
        status: transaction.status || data.status || null,
        amount: Number(transaction.amount ?? data.amount ?? 0),
        currency: transaction.currency || data.currency || null,
        restaurantId: metadata.restaurantId || null,
        table: metadata.table || null,
        customerName: metadata.customerName || null,
        paidAt: transaction.paid_at ? new Date(transaction.paid_at) : null,
        raw: data,
        webhookReceivedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
    }
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
    const result = await db.runTransaction(async (tx) => {
      const accessToken = createSessionAccessToken();
      const accessTokenHash = hashSessionAccessToken(accessToken);
      const accessTokenExpiresAt = Date.now() + 60 * 60 * 1000;
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
      let recycleSessionRef = null;
      if (currentSessionId) {
        const sessionRef = db.doc(
          `restaurants/${restaurantId}/tableSessions/${currentSessionId}`,
        );
        const sessionSnap = await tx.get(sessionRef);
        if (
          sessionSnap.exists &&
          ["open", "awaiting_payment", "transfer_reported"].includes(sessionSnap.data().status)
        ) {
          const session = sessionSnap.data();
          const lastActivity = toMillis(session.updatedAt || session.openedAt);
          if (lastActivity && Date.now() - lastActivity > SESSION_IDLE_MS) {
            tx.update(sessionRef, {
              status: "expired",
              expiredAt: FieldValue.serverTimestamp(),
              expiredReason: "idle",
              waiterCalledAt: null,
            });
          } else {

          const accessTokens = Array.isArray(session.accessTokens)
            ? session.accessTokens.filter((entry) => Number(entry.expiresAt) > Date.now())
            : [];
          accessTokens.push({ hash: accessTokenHash, expiresAt: accessTokenExpiresAt });
          tx.update(sessionRef, { accessTokens: accessTokens.slice(-20) });

          // Prepaid (pay-online) sessions have no staff-forced closing moment.
          // If every order on the session has been served, the party is done —
          // recycle: archive the old session and start fresh for the new scan.
          // Otherwise the next party would inherit a stranger's session.
          if (normalizePaymentMode(session.paymentMode) === "pay_online") {
            const ids = Array.isArray(session.orderIds) ? session.orderIds : [];
            if (ids.length > 0) {
              const orderSnaps = await Promise.all(
                ids.map((id) =>
                  tx.get(db.doc(`restaurants/${restaurantId}/orders/${id}`)),
                ),
              );
              // Cancelled orders are settled by definition — they never block recycling.
              const allServed = orderSnaps.every(
                (s) =>
                  s.exists &&
                  ["completed", "cancelled"].includes(s.data().status),
              );
              if (allServed) {
                recycleSessionRef = sessionRef; // close below, then create anew
              } else {
                return { sessionId: currentSessionId, accessToken }; // party still eating — rejoin
              }
            } else {
              return { sessionId: currentSessionId, accessToken }; // fresh prepaid session, nothing ordered yet
            }
          } else {
            return { sessionId: currentSessionId, accessToken }; // pay-at-table: staff closing is the boundary
          }
          }
        }
      }

      if (recycleSessionRef) {
        tx.update(recycleSessionRef, {
          status: "paid",
          paidVia: "online",
          closedAt: FieldValue.serverTimestamp(),
          closedByUid: null,
          waiterCalledAt: null,
        });
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
        checks: {},
        accessTokens: [{ hash: accessTokenHash, expiresAt: accessTokenExpiresAt }],
        paymentMode,
        paidVia: null,
        closedByUid: null,
      });
      tx.set(
        tableRef,
        { currentSessionId: newSessionRef.id, updatedAt: FieldValue.serverTimestamp() },
        { merge: true },
      );
      return { sessionId: newSessionRef.id, accessToken };
    });

    return res.json(result);
  } catch (err) {
    console.error("Open table session error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not open table session.",
    });
  }
});

// POST /place-order — server-authoritative pay-at-table order creation.
// The client supplies the cart, but the server owns prices, totals, and the
// atomic append to the table session.
app.post("/place-order", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const customerName = String(req.body?.customerName || "").trim().slice(0, 120);
  const email = String(req.body?.email || "").trim().slice(0, 160);
  const table = String(req.body?.table || "").trim();
  const allergies = String(req.body?.allergies || "").trim().slice(0, 500);
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  const requestedCheckId = String(req.body?.checkId || "");
  const checkSecret = String(req.body?.checkSecret || "");

  if (!restaurantId || !sessionId || !accessToken || !customerName || !table ||
      !validCheckId(requestedCheckId) || !validCheckSecret(checkSecret)) {
    return res.status(400).json({ error: "A valid table session, name, and table are required." });
  }
  if (!validateOrderItems(items)) {
    return res.status(400).json({ error: "Your order contains invalid items." });
  }

  try {
    const result = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists) {
        throw Object.assign(new Error("Table session not found."), { statusCode: 404 });
      }
      const session = sessionSnap.data();
      const tokenHash = hashSessionAccessToken(accessToken);
      const tokenValid = Array.isArray(session.accessTokens) && session.accessTokens.some(
        (entry) => entry.hash === tokenHash && Number(entry.expiresAt) > Date.now(),
      );
      if (!tokenValid || session.table !== table) {
        throw Object.assign(new Error("Your table session has expired. Please scan the QR code again."), { statusCode: 403 });
      }
      if (session.status !== "open") {
        throw Object.assign(new Error("This table is no longer accepting orders."), { statusCode: 409 });
      }
      if (checkState(session, requestedCheckId).status !== "open") {
        throw Object.assign(new Error("This check has requested payment. Ask staff to reopen it or start a new visit."), { statusCode: 409 });
      }
      if (!hasCheckAccess(session, requestedCheckId, checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }

      const menuSnap = await tx.get(db.collection(`restaurants/${restaurantId}/menu`));
      const menuByName = new Map(
        menuSnap.docs.map((doc) => [String(doc.data().name || "").trim(), doc.data()]),
      );
      const verifiedItems = items.map((item) => {
        const menuItem = menuByName.get(String(item.name || "").trim());
        if (!menuItem || menuItem.available === false) {
          throw Object.assign(new Error(`${item.name || "An item"} is no longer available.`), { statusCode: 409 });
        }
        const price = Number(menuItem.price);
        if (!Number.isFinite(price)) {
          throw Object.assign(new Error("A menu item has an invalid price."), { statusCode: 500 });
        }
        return { name: String(menuItem.name), price, qty: Number(item.qty) };
      });
      const total = calculateItemsTotal(verifiedItems);
      const orderRef = db.collection(`restaurants/${restaurantId}/orders`).doc();
      tx.set(orderRef, {
        customerName,
        email,
        table,
        allergies,
        items: verifiedItems,
        total,
        status: "pending",
        createdAt: FieldValue.serverTimestamp(),
        sessionId,
        checkId: requestedCheckId,
      });
      tx.update(sessionRef, {
        orderIds: FieldValue.arrayUnion(orderRef.id),
        totalBill: FieldValue.increment(total),
        checks: { ...(session.checks || {}), [requestedCheckId]: { status: "open", secretHash: hashCheckSecret(checkSecret) } },
        updatedAt: FieldValue.serverTimestamp(),
      });
      return { orderId: orderRef.id };
    });
    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Place order error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not place order." });
  }
});

// POST /staff-place-order — authenticated counter/waiter order entry for guests
// who are not ordering from their own phone. The server creates or reuses the
// table session, validates live menu prices, and records a private audit trail.
app.post(
  "/staff-place-order",
  rateLimit({ windowMs: 60_000, max: 40 }),
  requireFirebaseUser,
  async (req, res) => {
    const restaurantId = String(req.body?.restaurantId || "").trim();
    const table = String(req.body?.table || "").trim().slice(0, 40);
    const customerName = String(req.body?.customerName || "Walk-in guest")
      .trim()
      .slice(0, 120) || "Walk-in guest";
    const allergies = String(req.body?.allergies || "").trim().slice(0, 500);
    const requestId = String(req.body?.requestId || "").trim();
    const items = Array.isArray(req.body?.items) ? req.body.items : [];

    if (!restaurantId || !table || !/^[a-zA-Z0-9_-]{12,120}$/.test(requestId)) {
      return res.status(400).json({ error: "A table and valid order request are required." });
    }
    if (!validateOrderItems(items)) {
      return res.status(400).json({ error: "The order contains invalid items." });
    }

    try {
      const uid = req.firebaseUser.uid;
      if (!(await userCanOperate(uid, restaurantId))) {
        return res.status(403).json({ error: "You are not authorised to place orders here." });
      }

      const userSnap = await db.doc(`users/${uid}`).get();
      const userData = userSnap.exists ? userSnap.data() : {};
      const actorName = String(
        userData.name || userData.displayName || req.firebaseUser.name || req.firebaseUser.email || "Staff",
      ).slice(0, 120);

      const result = await db.runTransaction(async (tx) => {
        const requestRef = db.doc(
          `restaurants/${restaurantId}/staffOrderRequests/${requestId}`,
        );
        const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
        const tableRef = db.doc(`restaurants/${restaurantId}/tables/${table}`);
        const [requestSnap, profileSnap, tableSnap] = await Promise.all([
          tx.get(requestRef),
          tx.get(profileRef),
          tx.get(tableRef),
        ]);

        if (requestSnap.exists) {
          return { ...requestSnap.data(), duplicate: true };
        }
        if (!profileSnap.exists || !isVenueActive(profileSnap.data())) {
          throw Object.assign(new Error("This restaurant is not accepting orders right now."), {
            statusCode: 403,
          });
        }

        let sessionRef = null;
        let createdSession = false;
        let existingSession = null;
        const currentSessionId = tableSnap.exists
          ? tableSnap.data().currentSessionId || null
          : null;
        if (currentSessionId) {
          const currentRef = db.doc(
            `restaurants/${restaurantId}/tableSessions/${currentSessionId}`,
          );
          const currentSnap = await tx.get(currentRef);
          if (currentSnap.exists) {
            const current = currentSnap.data();
            if (current.status === "open") {
              sessionRef = currentRef;
              existingSession = current;
            } else if (["awaiting_payment", "transfer_reported"].includes(current.status)) {
              throw Object.assign(
                new Error(`Table ${table} has an unsettled bill. Close it before starting another order.`),
                { statusCode: 409 },
              );
            }
          }
        }

        const menuSnap = await tx.get(
          db.collection(`restaurants/${restaurantId}/menu`),
        );
        const menuByName = new Map(
          menuSnap.docs.map((menuDoc) => [
            String(menuDoc.data().name || "").trim(),
            menuDoc.data(),
          ]),
        );
        const verifiedItems = items.map((item) => {
          const menuItem = menuByName.get(String(item.name || "").trim());
          if (!menuItem || menuItem.available === false) {
            throw Object.assign(
              new Error(`${item.name || "An item"} is no longer available.`),
              { statusCode: 409 },
            );
          }
          const price = Number(menuItem.price);
          if (!Number.isFinite(price)) {
            throw Object.assign(new Error("A menu item has an invalid price."), {
              statusCode: 500,
            });
          }
          return {
            name: String(menuItem.name),
            price,
            qty: Number(item.qty),
            station: menuItem.station === "bar" ? "bar" : "kitchen",
          };
        });

        if (!sessionRef) {
          sessionRef = db.collection(`restaurants/${restaurantId}/tableSessions`).doc();
          createdSession = true;
          tx.set(
            tableRef,
            {
              currentSessionId: sessionRef.id,
              createdAt: tableSnap.exists
                ? tableSnap.data().createdAt || FieldValue.serverTimestamp()
                : FieldValue.serverTimestamp(),
              updatedAt: FieldValue.serverTimestamp(),
            },
            { merge: true },
          );
        }

        const total = calculateItemsTotal(verifiedItems);
        const orderRef = db.collection(`restaurants/${restaurantId}/orders`).doc();
        const staffCheckId = `c_${crypto.randomBytes(16).toString("hex")}`;
        const auditRef = db.doc(
          `restaurants/${restaurantId}/orderAudit/${orderRef.id}`,
        );
        tx.set(orderRef, {
          customerName,
          email: "",
          table,
          allergies,
          items: verifiedItems,
          total,
          status: "pending",
          createdAt: FieldValue.serverTimestamp(),
          sessionId: sessionRef.id,
          checkId: staffCheckId,
          orderSource: "staff",
          createdByName: actorName,
        });
        tx.set(auditRef, {
          action: "staff_order_created",
          orderId: orderRef.id,
          sessionId: sessionRef.id,
          actorUid: uid,
          actorEmail: req.firebaseUser.email || "",
          actorName,
          requestId,
          createdAt: FieldValue.serverTimestamp(),
        });
        tx.set(requestRef, {
          orderId: orderRef.id,
          sessionId: sessionRef.id,
          table,
          total,
          createdAt: FieldValue.serverTimestamp(),
        });
        if (createdSession) {
          tx.set(sessionRef, {
            table,
            status: "open",
            openedAt: FieldValue.serverTimestamp(),
            billRequestedAt: null,
            closedAt: null,
            totalBill: total,
            orderIds: [orderRef.id],
            checks: { [staffCheckId]: { status: "open" } },
            accessTokens: [],
            paymentMode: normalizePaymentMode(profileSnap.data()?.paymentMode),
            paidVia: null,
            closedByUid: null,
            updatedAt: FieldValue.serverTimestamp(),
          });
        } else {
          tx.update(sessionRef, {
            orderIds: FieldValue.arrayUnion(orderRef.id),
            totalBill: FieldValue.increment(total),
            checks: { ...(existingSession.checks || {}), [staffCheckId]: { status: "open" } },
            updatedAt: FieldValue.serverTimestamp(),
          });
        }

        return { orderId: orderRef.id, sessionId: sessionRef.id, table, total };
      });

      return res.json({ success: true, ...result });
    } catch (err) {
      console.error("Staff place order error:", err);
      return res.status(err.statusCode || 500).json({
        error: err.message || "The staff order could not be placed.",
      });
    }
  },
);

// POST /edit-order — recalculate a pending order and adjust the table atomically.
app.post("/edit-order", rateLimit({ windowMs: 60_000, max: 20 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  if (!restaurantId || !orderId || !sessionId || !accessToken || !validateOrderItems(items)) {
    return res.status(400).json({ error: "Invalid order update." });
  }
  try {
    const result = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap, menuSnap] = await Promise.all([
        tx.get(sessionRef),
        tx.get(orderRef),
        tx.get(db.collection(`restaurants/${restaurantId}/menu`)),
      ]);
      const session = sessionSnap.data();
      const tokenHash = hashSessionAccessToken(accessToken);
      const tokenValid = sessionSnap.exists && Array.isArray(session.accessTokens) && session.accessTokens.some(
        (entry) => entry.hash === tokenHash && Number(entry.expiresAt) > Date.now(),
      );
      if (!tokenValid || session.status !== "open" || !orderSnap.exists) {
        throw Object.assign(new Error("This order can no longer be edited."), { statusCode: 409 });
      }
      const order = orderSnap.data();
      if (!hasCheckAccess(session, orderCheckId(order), checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }
      if (order.sessionId !== sessionId || order.status !== "pending" || order.paymentStatus === "paid" ||
          checkState(session, orderCheckId(order)).status !== "open") {
        throw Object.assign(new Error("This order can no longer be edited."), { statusCode: 409 });
      }
      const menuByName = new Map(menuSnap.docs.map((doc) => [String(doc.data().name || "").trim(), doc.data()]));
      const verifiedItems = items.map((item) => {
        const menuItem = menuByName.get(String(item.name || "").trim());
        if (!menuItem || menuItem.available === false) {
          throw Object.assign(new Error(`${item.name || "An item"} is no longer available.`), { statusCode: 409 });
        }
        return { name: String(menuItem.name), price: Number(menuItem.price), qty: Number(item.qty) };
      });
      const nextTotal = calculateItemsTotal(verifiedItems);
      tx.update(orderRef, { items: verifiedItems, total: nextTotal, updatedAt: FieldValue.serverTimestamp() });
      tx.update(sessionRef, {
        totalBill: FieldValue.increment(nextTotal - Number(order.total || 0)),
        updatedAt: FieldValue.serverTimestamp(),
      });
      return { total: nextTotal };
    });
    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Edit order error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not edit order." });
  }
});

// POST /cancel-order — cancel a pending unpaid order and decrement the bill.
app.post("/cancel-order", rateLimit({ windowMs: 60_000, max: 10 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  if (!restaurantId || !orderId || !sessionId || !accessToken) {
    return res.status(400).json({ error: "Invalid cancellation request." });
  }
  try {
    await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      const session = sessionSnap.data();
      const tokenHash = hashSessionAccessToken(accessToken);
      const tokenValid = sessionSnap.exists && Array.isArray(session.accessTokens) && session.accessTokens.some(
        (entry) => entry.hash === tokenHash && Number(entry.expiresAt) > Date.now(),
      );
      if (!tokenValid || session.status !== "open" || !orderSnap.exists) {
        throw Object.assign(new Error("This order can no longer be cancelled."), { statusCode: 409 });
      }
      const order = orderSnap.data();
      if (!hasCheckAccess(session, orderCheckId(order), checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }
      if (order.sessionId !== sessionId || order.status !== "pending" || order.paymentStatus === "paid" ||
          checkState(session, orderCheckId(order)).status !== "open") {
        throw Object.assign(new Error("This order can no longer be cancelled."), { statusCode: 409 });
      }
      tx.update(orderRef, { status: "cancelled", updatedAt: FieldValue.serverTimestamp() });
      tx.update(sessionRef, {
        totalBill: FieldValue.increment(-Number(order.total || 0)),
        updatedAt: FieldValue.serverTimestamp(),
      });
    });
    return res.json({ success: true });
  } catch (err) {
    console.error("Cancel order error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not cancel order." });
  }
});

// A diner may briefly expose their bill to other authenticated guests at the
// same table. Only a short label and the outstanding total are returned.
app.post("/group-payment-sharing", rateLimit({ windowMs: 60_000, max: 20 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  const enabled = req.body?.enabled === true;
  if (!restaurantId || !sessionId || !orderId || !accessToken) {
    return res.status(400).json({ error: "A valid order and table session are required." });
  }

  try {
    const result = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      const session = sessionSnap.data();
      const order = orderSnap.data();
      if (!session || !order || order.sessionId !== sessionId ||
          !hasValidSessionToken(session, accessToken)) {
        throw Object.assign(new Error("Order access has expired."), { statusCode: 403 });
      }
      if (session.status !== "open") {
        throw Object.assign(new Error("This table can no longer share bills."), { statusCode: 409 });
      }
      const checkId = orderCheckId(order);
      if (!validCheckId(checkId) || !hasCheckAccess(session, checkId, checkSecret)) {
        throw Object.assign(new Error("This bill cannot be shared."), { statusCode: 403 });
      }
      const currentCheck = checkState(session, checkId);
      if (currentCheck.status !== "open" || order.status === "cancelled" || order.paymentStatus === "paid") {
        throw Object.assign(new Error("Only an open unpaid bill can be shared."), { statusCode: 409 });
      }
      const shareUntil = enabled ? new Date(Date.now() + GROUP_PAYMENT_SHARE_MS) : null;
      tx.update(sessionRef, {
        checks: {
          ...(session.checks || {}),
          [checkId]: {
            ...currentCheck,
            groupPaymentShareUntil: shareUntil,
            groupPaymentShareLabel: enabled
              ? String(order.customerName || "Guest").trim().split(/\s+/)[0].slice(0, 40)
              : null,
          },
        },
        updatedAt: FieldValue.serverTimestamp(),
      });
      return { enabled, shareUntil: shareUntil?.toISOString() || null };
    });
    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Group payment sharing error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not update bill sharing." });
  }
});

app.get("/shared-table-bills", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  const sessionId = String(req.query.sessionId || "").trim();
  const orderId = String(req.query.orderId || "").trim();
  const accessToken = String(req.query.accessToken || "").trim();
  const checkSecret = String(req.query.checkSecret || "");
  if (!restaurantId || !sessionId || !orderId || !accessToken) {
    return res.status(400).json({ error: "A valid order and table session are required." });
  }

  try {
    const [sessionSnap, orderSnap] = await Promise.all([
      db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`).get(),
      db.doc(`restaurants/${restaurantId}/orders/${orderId}`).get(),
    ]);
    const session = sessionSnap.data();
    const order = orderSnap.data();
    if (!session || !order || order.sessionId !== sessionId ||
        !hasValidSessionToken(session, accessToken)) {
      return res.status(403).json({ error: "Order access has expired." });
    }
    if (session.status !== "open") {
      return res.status(409).json({ error: "This table can no longer start a combined payment." });
    }
    const ownCheckId = orderCheckId(order);
    if (!hasCheckAccess(session, ownCheckId, checkSecret)) {
      return res.status(403).json({ error: "This bill belongs to another guest." });
    }
    const orderSnaps = await Promise.all((session.orderIds || []).map((id) =>
      db.doc(`restaurants/${restaurantId}/orders/${id}`).get(),
    ));
    const groups = new Map();
    orderSnaps.forEach((snap) => {
      if (!snap.exists) return;
      const item = snap.data();
      const checkId = orderCheckId(item);
      const state = checkState(session, checkId);
      if (checkId === ownCheckId || !validCheckId(checkId) || state.status !== "open" ||
          toMillis(state.groupPaymentShareUntil) <= Date.now() ||
          item.status === "cancelled" || item.paymentStatus === "paid") return;
      if (!groups.has(checkId)) {
        groups.set(checkId, {
          checkId,
          label: state.groupPaymentShareLabel || "Guest",
          total: 0,
          orderCount: 0,
          shareUntil: new Date(toMillis(state.groupPaymentShareUntil)).toISOString(),
        });
      }
      const group = groups.get(checkId);
      group.total += Number(item.total || 0);
      group.orderCount += 1;
    });
    return res.json({ bills: [...groups.values()] });
  } catch (err) {
    console.error("Shared table bills error:", err);
    return res.status(500).json({ error: "Could not load shared bills." });
  }
});

// POST /request-bill — customer-triggered soft lock, idempotent (public)
app.post("/request-bill", async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  const includedCheckIds = [...new Set(
    Array.isArray(req.body?.includedCheckIds) ? req.body.includedCheckIds.map(String) : [],
  )];
  if (!restaurantId || !sessionId || !orderId || !accessToken ||
      includedCheckIds.some((id) => !validCheckId(id))) {
    return res.status(400).json({ error: "A valid order and table session are required." });
  }

  try {
    const result = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      if (!sessionSnap.exists || !orderSnap.exists || orderSnap.data().sessionId !== sessionId ||
          !hasValidSessionToken(sessionSnap.data(), accessToken)) {
        throw Object.assign(new Error("Order access has expired. Please ask a waiter for the bill."), { statusCode: 403 });
      }
      const session = sessionSnap.data();
      const checkId = orderCheckId(orderSnap.data());
      if (!hasCheckAccess(session, checkId, checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }
      if (orderSnap.data().status === "cancelled" || orderSnap.data().paymentStatus === "paid") {
        throw Object.assign(new Error("This order has no outstanding bill."), { statusCode: 409 });
      }
      const currentCheck = checkState(session, checkId);
      if (currentCheck.status === "paid") return { status: "paid", checkId };
      if (currentCheck.status !== "open") return { status: currentCheck.status, checkId };
      if (session.status !== "open") {
        throw Object.assign(new Error("This table can no longer request a bill."), { statusCode: 409 });
      }
      const targetCheckIds = [...new Set([checkId, ...includedCheckIds.filter((id) => id !== checkId)])];
      const orderSnaps = await Promise.all((session.orderIds || []).map((id) =>
        tx.get(db.doc(`restaurants/${restaurantId}/orders/${id}`)),
      ));
      const targetOrders = orderSnaps.filter((snap) => snap.exists &&
        targetCheckIds.includes(orderCheckId(snap.data())) &&
        snap.data().status !== "cancelled" && snap.data().paymentStatus !== "paid");
      if (targetCheckIds.some((id) => !targetOrders.some((snap) => orderCheckId(snap.data()) === id))) {
        throw Object.assign(new Error("One of the selected bills is no longer available."), { statusCode: 409 });
      }
      for (const targetId of targetCheckIds) {
        const targetState = checkState(session, targetId);
        if (targetState.status !== "open" ||
            (targetId !== checkId && toMillis(targetState.groupPaymentShareUntil) <= Date.now())) {
          throw Object.assign(new Error("One of the selected bills is no longer shared or is already being paid."), { statusCode: 409 });
        }
      }
      const paymentGroupId = targetCheckIds.length > 1
        ? `pg_${crypto.randomBytes(16).toString("hex")}`
        : null;
      const checks = { ...(session.checks || {}) };
      targetCheckIds.forEach((targetId) => {
        checks[targetId] = {
          ...checkState(session, targetId),
          status: "awaiting_payment",
          billRequestedAt: new Date(),
          paymentGroupId,
          paymentGroupPayerCheckId: checkId,
          groupPaymentShareUntil: null,
        };
      });
      tx.update(sessionRef, {
        checks,
        updatedAt: FieldValue.serverTimestamp(),
      });
      return {
        status: "awaiting_payment",
        checkId,
        paymentGroupId,
        billCount: targetCheckIds.length,
        amount: targetOrders.reduce((sum, snap) => sum + Number(snap.data().total || 0), 0),
      };
    });

    return res.json(result);
  } catch (err) {
    console.error("Request bill error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not request bill.",
    });
  }
});

// GET /transfer-details — return bank details only for an active bill session.
// Full account numbers never live in the public restaurant profile.
app.get("/transfer-details", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  const sessionId = String(req.query.sessionId || "").trim();
  const orderId = String(req.query.orderId || "").trim();
  const accessToken = String(req.query.accessToken || "").trim();
  const checkSecret = String(req.query.checkSecret || "");
  if (!restaurantId || !sessionId || !orderId || !accessToken) {
    return res.status(400).json({ error: "A valid order and table session are required." });
  }

  try {
    const [sessionSnap, orderSnap] = await Promise.all([
      db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`).get(),
      db.doc(`restaurants/${restaurantId}/orders/${orderId}`).get(),
    ]);
    const session = sessionSnap.data();
    if (!session || !orderSnap.exists || orderSnap.data().sessionId !== sessionId ||
        !hasValidSessionToken(session, accessToken) ||
        !hasCheckAccess(session, orderCheckId(orderSnap.data()), checkSecret) ||
        !["awaiting_payment", "transfer_reported"].includes(checkState(session, orderCheckId(orderSnap.data())).status)) {
      return res.status(409).json({ error: "Request the bill before viewing transfer details." });
    }
    const ownCheckId = orderCheckId(orderSnap.data());
    const ownCheck = checkState(session, ownCheckId);
    if (ownCheck.paymentGroupId && ownCheck.paymentGroupPayerCheckId !== ownCheckId) {
      return res.status(403).json({ error: "Another guest is handling this combined payment." });
    }
    const groupCheckIds = ownCheck.paymentGroupId
      ? Object.entries(session.checks || {})
          .filter(([, state]) => state.paymentGroupId === ownCheck.paymentGroupId)
          .map(([id]) => id)
      : [ownCheckId];
    const [privateSnap, ...orderSnaps] = await Promise.all([
      db.doc(`restaurants/${restaurantId}/profile/private`).get(),
      ...(session.orderIds || []).map((id) => db.doc(`restaurants/${restaurantId}/orders/${id}`).get()),
    ]);
    const bank = privateSnap.exists ? privateSnap.data() : {};
    if (!bank.bankName || !bank.accountName || !bank.accountNumber) {
      return res.status(404).json({ error: "Bank transfer is not configured for this restaurant." });
    }
    return res.json({
      bankName: String(bank.bankName),
      accountName: String(bank.accountName),
      accountNumber: String(bank.accountNumber),
      amount: orderSnaps.filter((snap) => snap.exists &&
        groupCheckIds.includes(orderCheckId(snap.data())) &&
        snap.data().status !== "cancelled" && snap.data().paymentStatus !== "paid")
        .reduce((sum, snap) => sum + Number(snap.data().total || 0), 0),
      billCount: groupCheckIds.length,
    });
  } catch (err) {
    console.error("Transfer details error:", err);
    return res.status(500).json({ error: "Could not load transfer details." });
  }
});

// POST /report-transfer — diner reports a transfer; staff still has to confirm it.
app.post("/report-transfer", rateLimit({ windowMs: 60_000, max: 5 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  const reference = String(req.body?.reference || "").trim().slice(0, 80);
  if (!restaurantId || !sessionId || !orderId || !accessToken || !reference) {
    return res.status(400).json({ error: "Order and transfer reference are required." });
  }

  try {
    await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      const session = sessionSnap.data();
      if (!session || !orderSnap.exists || orderSnap.data().sessionId !== sessionId ||
          !hasValidSessionToken(session, accessToken)) {
        throw Object.assign(new Error("Order access has expired."), { statusCode: 403 });
      }
      const checkId = orderCheckId(orderSnap.data());
      if (!hasCheckAccess(session, checkId, checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }
      const currentCheck = checkState(session, checkId);
      if (currentCheck.status !== "awaiting_payment") {
        throw Object.assign(new Error("This check is not awaiting payment."), { statusCode: 409 });
      }
      if (currentCheck.paymentGroupId && currentCheck.paymentGroupPayerCheckId !== checkId) {
        throw Object.assign(new Error("Another guest is handling this combined payment."), { statusCode: 403 });
      }
      const groupCheckIds = currentCheck.paymentGroupId
        ? Object.entries(session.checks || {})
            .filter(([, state]) => state.paymentGroupId === currentCheck.paymentGroupId)
            .map(([id]) => id)
        : [checkId];
      if (groupCheckIds.some((id) => checkState(session, id).status !== "awaiting_payment")) {
        throw Object.assign(new Error("One of these bills is no longer awaiting payment."), { statusCode: 409 });
      }
      const checks = { ...(session.checks || {}) };
      groupCheckIds.forEach((id) => {
        checks[id] = {
          ...checkState(session, id),
          status: "transfer_reported",
          transferReportedAt: new Date(),
          transferReference: reference,
        };
      });
      tx.update(sessionRef, {
        checks,
        updatedAt: FieldValue.serverTimestamp(),
      });
    });
    return res.json({ success: true, status: "transfer_reported" });
  } catch (err) {
    console.error("Report transfer error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not report transfer." });
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

// Staff may collect one check or all outstanding checks together. Each order is
// marked paid exactly once; the table is released after the last check settles.
app.post("/settle-checks", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderIds = [...new Set(Array.isArray(req.body?.orderIds) ? req.body.orderIds.map(String) : [])];
  const checkIds = [...new Set(Array.isArray(req.body?.checkIds) ? req.body.checkIds : [])];
  const paidVia = String(req.body?.paidVia || "");
  if (!restaurantId || !sessionId || (!orderIds.length && !checkIds.length) ||
      checkIds.some((id) => id !== LEGACY_CHECK_ID && !validCheckId(id)) ||
      !["cash", "pos", "transfer"].includes(paidVia)) {
    return res.status(400).json({ error: "Select a valid bill and payment method." });
  }
  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }
    const receipt = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists || !OPEN_TABLE_SESSION_STATUSES.includes(sessionSnap.data().status)) {
        throw Object.assign(new Error("This table is already closed."), { statusCode: 409 });
      }
      const session = sessionSnap.data();
      const orderRefs = (session.orderIds || []).map((id) => db.doc(`restaurants/${restaurantId}/orders/${id}`));
      const [orderSnaps, profileSnap] = await Promise.all([
        Promise.all(orderRefs.map((ref) => tx.get(ref))),
        tx.get(db.doc(`restaurants/${restaurantId}/profile/info`)),
      ]);
      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${session.table}`);
      const tableSnap = await tx.get(tableRef);
      const active = orderSnaps.filter((snap) => snap.exists && snap.data().status !== "cancelled");
      const unpaid = active.filter((snap) => snap.data().paymentStatus !== "paid");
      const selected = orderIds.length
        ? unpaid.filter((snap) => orderIds.includes(snap.id))
        : unpaid.filter((snap) => checkIds.includes(orderCheckId(snap.data())));
      if (!selected.length ||
          (orderIds.length && orderIds.some((id) => !selected.some((snap) => snap.id === id))) ||
          (!orderIds.length && checkIds.some((id) => !selected.some((snap) => orderCheckId(snap.data()) === id)))) {
        throw Object.assign(new Error("This bill has no unpaid orders."), { statusCode: 409 });
      }
      const selectedCheckIds = [...new Set(selected.map((snap) => orderCheckId(snap.data())))];
      const selectedPaymentGroups = [...new Set(selectedCheckIds
        .map((id) => checkState(session, id).paymentGroupId)
        .filter(Boolean))];
      for (const paymentGroupId of selectedPaymentGroups) {
        const groupCheckIds = Object.entries(session.checks || {})
          .filter(([, state]) => state.paymentGroupId === paymentGroupId && state.status !== "paid")
          .map(([id]) => id);
        if (groupCheckIds.some((id) => !selectedCheckIds.includes(id))) {
          throw Object.assign(
            new Error("All bills in this combined payment must be confirmed together."),
            { statusCode: 409 },
          );
        }
      }
      const reportedChecks = selectedCheckIds.filter((id) => checkState(session, id).status === "transfer_reported");
      if (paidVia === "transfer" && (reportedChecks.length === 0 ||
          (!selectedCheckIds.every((id) => reportedChecks.includes(id)) && selected.length !== unpaid.length))) {
        throw Object.assign(new Error("A transfer must be reported for this bill. For one payer covering every bill, select all outstanding orders and verify the full amount."), { statusCode: 409 });
      }
      const amount = selected.reduce((sum, snap) => sum + Number(snap.data().total || 0), 0);
      const allSettled = selected.length === unpaid.length;
      const selectedOrderIds = new Set(selected.map((snap) => snap.id));
      const settlementMethods = new Set(active.map((snap) =>
        selectedOrderIds.has(snap.id) ? paidVia : snap.data().paidVia,
      ).filter(Boolean));
      const checks = { ...(session.checks || {}) };
      selectedCheckIds.forEach((id) => {
        const unpaidForCheck = unpaid.filter((snap) => orderCheckId(snap.data()) === id);
        const selectedForCheck = selected.filter((snap) => orderCheckId(snap.data()) === id);
        const checkAmount = selectedForCheck
          .reduce((sum, snap) => sum + Number(snap.data().total || 0), 0);
        // Legacy orders share one fallback check state. Do not mark that state
        // paid while another guest's legacy bill is still outstanding.
        if (selectedForCheck.length === unpaidForCheck.length) {
          checks[id] = { ...checkState(session, id), status: "paid", paidVia, paidAt: new Date(), amount: checkAmount,
            settledOrders: selectedForCheck.length };
        }
      });
      selected.forEach((snap) => tx.update(snap.ref, {
        paymentStatus: "paid", paidVia, paidAt: FieldValue.serverTimestamp(),
      }));
      tx.update(sessionRef, {
        checks,
        amountPaid: FieldValue.increment(amount),
        ...(allSettled ? {
          status: "paid", closedAt: FieldValue.serverTimestamp(),
          paidVia: settlementMethods.size > 1 ? "mixed" : [...settlementMethods][0] || paidVia,
          closedByUid: req.firebaseUser.uid, waiterCalledAt: null,
        } : {}),
        updatedAt: FieldValue.serverTimestamp(),
      });
      if (allSettled) {
        if (tableSnap.data()?.currentSessionId === sessionId) {
          tx.set(tableRef, { currentSessionId: null, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
        }
      }
      const dayKey = lagosDayKey();
      tx.set(db.doc(`restaurants/${restaurantId}/dailySummaries/${dayKey}`), {
        dateKey: dayKey,
        totalRevenue: FieldValue.increment(amount),
        [paymentRevenueField(paidVia)]: FieldValue.increment(amount),
        settledOrders: FieldValue.increment(selected.length),
        ...(allSettled ? { settledTables: FieldValue.increment(1) } : {}),
        lastSettlementAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
      return {
        restaurantName: profileSnap.data()?.name || restaurantId,
        table: session.table,
        orders: selected.map((snap) => ({
          customerName: snap.data().customerName || "Guest",
          items: snap.data().items || [],
          total: Number(snap.data().total || 0),
        })),
        totalBill: amount,
        settledOrderIds: selected.map((snap) => snap.id),
        paidVia,
        tableClosed: allSettled,
        closedAt: new Date().toISOString(),
      };
    });
    return res.json({ success: true, ...receipt });
  } catch (err) {
    console.error("Settle checks error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not settle checks." });
  }
});

// End an unused table visit without creating a payment or receipt. This route
// is intentionally limited to sessions where every linked order was cancelled.
app.post("/close-empty-table-session", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  if (!restaurantId || !sessionId) {
    return res.status(400).json({ error: "A restaurant and table session are required." });
  }

  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }

    const result = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists || !OPEN_TABLE_SESSION_STATUSES.includes(sessionSnap.data().status)) {
        throw Object.assign(new Error("This table is already closed."), { statusCode: 409 });
      }

      const session = sessionSnap.data();
      const orderRefs = (session.orderIds || []).map((id) =>
        db.doc(`restaurants/${restaurantId}/orders/${id}`),
      );
      const orderSnaps = await Promise.all(orderRefs.map((ref) => tx.get(ref)));
      const billableOrders = orderSnaps.filter(
        (snap) => snap.exists &&
          (snap.data().status !== "cancelled" || snap.data().paymentStatus === "paid"),
      );
      if (billableOrders.length > 0 || Number(session.amountPaid || 0) > 0) {
        throw Object.assign(
          new Error("This table has billable orders. Collect payment instead of closing it without charge."),
          { statusCode: 409 },
        );
      }

      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${session.table}`);
      const tableSnap = await tx.get(tableRef);
      tx.update(sessionRef, {
        status: "closed",
        totalBill: 0,
        amountPaid: 0,
        paidVia: null,
        closeReason: "all_orders_cancelled",
        closedAt: FieldValue.serverTimestamp(),
        closedByUid: req.firebaseUser.uid,
        waiterCalledAt: null,
        updatedAt: FieldValue.serverTimestamp(),
      });
      if (tableSnap.exists && tableSnap.data()?.currentSessionId === sessionId) {
        tx.set(
          tableRef,
          { currentSessionId: null, updatedAt: FieldValue.serverTimestamp() },
          { merge: true },
        );
      }

      return { table: session.table };
    });

    return res.json({ success: true, table: result.table, receipt: null });
  } catch (err) {
    console.error("Close empty table session error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not close this table.",
    });
  }
});

app.post("/move-order-check", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const targetCheckId = String(req.body?.targetCheckId || "").trim();
  if (!restaurantId || !sessionId || !orderId || !validCheckId(targetCheckId)) {
    return res.status(400).json({ error: "Select an order and an open check." });
  }
  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }
    await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      const session = sessionSnap.data();
      const order = orderSnap.data();
      if (!session || !order || session.status !== "open" || order.sessionId !== sessionId ||
          order.status === "cancelled" || order.paymentStatus === "paid" ||
          !session.orderIds?.includes(orderId) ||
          checkState(session, orderCheckId(order)).status !== "open" ||
          checkState(session, targetCheckId).status !== "open") {
        throw Object.assign(new Error("Only unpaid orders on open checks can be moved."), { statusCode: 409 });
      }
      const targetExists = Object.prototype.hasOwnProperty.call(session.checks || {}, targetCheckId);
      if (!targetExists) {
        throw Object.assign(new Error("Target check does not exist on this table."), { statusCode: 409 });
      }
      tx.update(orderRef, { checkId: targetCheckId, updatedAt: FieldValue.serverTimestamp() });
      tx.update(sessionRef, {
        checks: { ...(session.checks || {}), [targetCheckId]: { status: "open" } },
        updatedAt: FieldValue.serverTimestamp(),
      });
    });
    return res.json({ success: true });
  } catch (err) {
    console.error("Move order check error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not move order." });
  }
});

// Retired in favor of check-level settlement. Do not accept client-supplied totals.
app.post("/close-table-session", requireFirebaseUser, (_req, res) => {
  return res.status(410).json({ error: "Use check-level settlement to close a table." });
});

// POST /rebuild-daily-summaries — management-only historical backfill. This is
// intentionally manual: the dashboard always reads tiny pre-aggregated docs,
// never every historical order/session.
app.post("/rebuild-daily-summaries", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const requestedDays = Number(req.body?.days || 7);
  const days = Math.max(1, Math.min(90, Number.isFinite(requestedDays) ? requestedDays : 7));

  if (!restaurantId) {
    return res.status(400).json({ error: "restaurantId is required" });
  }

  try {
    if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant" });
    }

    const start = new Date();
    start.setDate(start.getDate() - (days - 1));
    start.setHours(0, 0, 0, 0);
    const sessionCollection = db.collection(`restaurants/${restaurantId}/tableSessions`);
    const [closedSessions, updatedSessions] = await Promise.all([
      sessionCollection.where("closedAt", ">=", start).get(),
      sessionCollection.where("updatedAt", ">=", start).get(),
    ]);
    const sessions = new Map([...closedSessions.docs, ...updatedSessions.docs].map((snap) => [snap.id, snap]));
    const totals = new Map();
    const summaryFor = (dayKey) => {
      if (!totals.has(dayKey)) totals.set(dayKey, {
        totalRevenue: 0, cashRevenue: 0, posRevenue: 0, transferRevenue: 0,
        onlineRevenue: 0, otherRevenue: 0, settledTables: 0, settledOrders: 0,
      });
      return totals.get(dayKey);
    };

    sessions.forEach((snap) => {
      const session = snap.data();
      const paidChecks = Object.values(session.checks || {}).filter((check) =>
        check.status === "paid" && Number.isFinite(Number(check.amount)));
      if (paidChecks.length) {
        paidChecks.filter((check) => toMillis(check.paidAt) >= start.getTime()).forEach((check) => {
          const current = summaryFor(lagosDayKey(toMillis(check.paidAt)));
          current.totalRevenue += Number(check.amount);
          current[paymentRevenueField(check.paidVia)] += Number(check.amount);
          current.settledOrders += Number(check.settledOrders || 0);
        });
        if (session.status === "paid" && toMillis(session.closedAt) >= start.getTime()) {
          summaryFor(lagosDayKey(toMillis(session.closedAt))).settledTables += 1;
        }
        return;
      }
      if (session.status !== "paid" || toMillis(session.closedAt) < start.getTime()) return;
      const total = Number(session.totalBill);
      if (!Number.isFinite(total) || total < 0) return;
      const current = summaryFor(lagosDayKey(toMillis(session.closedAt)));
      current.totalRevenue += total;
      current[paymentRevenueField(session.paidVia)] += total;
      current.settledTables += 1;
      current.settledOrders += Array.isArray(session.orderIds) ? session.orderIds.length : 0;
    });

    const writes = [...totals.entries()];
    for (let index = 0; index < writes.length; index += 450) {
      const batch = db.batch();
      writes.slice(index, index + 450).forEach(([dayKey, data]) => {
        batch.set(
          db.doc(`restaurants/${restaurantId}/dailySummaries/${dayKey}`),
          {
            dateKey: dayKey,
            ...data,
            rebuiltAt: FieldValue.serverTimestamp(),
            updatedAt: FieldValue.serverTimestamp(),
          },
          { merge: true },
        );
      });
      await batch.commit();
    }

    return res.json({ success: true, days, summariesUpdated: writes.length });
  } catch (err) {
    console.error("Rebuild daily summaries error:", err);
    return res.status(500).json({ error: "Could not rebuild daily summaries." });
  }
});

app.post("/finalize-online-payment", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  return res.status(410).json({
    success: false,
    error: "Diner online payments are temporarily unavailable.",
  });

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
      let isNewSession = false;
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
        isNewSession = true;
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

      // Paying online settles the ORDER, not the table: the session stays open
      // so the same party can keep ordering (each order prepaid) until staff
      // close the table. Closing terminally here broke follow-up orders.
      tx.set(
        sessionRef,
        {
          table: cleanedTable,
          ...(isNewSession
            ? {
                status: "open",
                openedAt: FieldValue.serverTimestamp(),
                billRequestedAt: null,
                closedAt: null,
                paidVia: null,
                closedByUid: null,
              }
            : {}),
          updatedAt: FieldValue.serverTimestamp(),
          totalBill: nextTotalBill,
          orderIds: [...existingOrderIds, orderRef.id],
          paymentMode: "pay_online",
          lastPaymentRef: cleanedReference,
        },
        { merge: true },
      );

      // Register a freshly-created session on the table so rescans rejoin it.
      if (isNewSession) {
        tx.set(
          db.doc(`restaurants/${cleanedRestaurantId}/tables/${cleanedTable}`),
          {
            currentSessionId: sessionRef.id,
            updatedAt: FieldValue.serverTimestamp(),
          },
          { merge: true },
        );
      }

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
