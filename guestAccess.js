const crypto = require("node:crypto");

const hash = (value) => crypto.createHash("sha256").update(String(value || "")).digest("hex");
const validCheckId = (value) => /^c_[a-f0-9]{32}$/.test(String(value || ""));
const validCheckSecret = (value) => /^[a-f0-9]{64}$/.test(String(value || ""));

// A private check secret is a read capability for this visit, including after
// collection. Short-lived table tokens are still required for mutations.
function canReadGuestCheck(session, checkId, secret, accessToken, now = Date.now()) {
  if (!validCheckId(checkId) || !validCheckSecret(secret)) return false;
  const check = session.checks?.[checkId];
  if (check) {
    if (!check.secretHash) return false; // Staff/legacy checks are not public.
    const supplied = Buffer.from(hash(secret), "hex");
    const expected = Buffer.from(check.secretHash, "hex");
    return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
  }
  // Before the first order, expose only an empty personal bill to a table guest.
  return Boolean(accessToken) && (session.accessTokens || []).some(
    (token) => token.hash === hash(accessToken) && Number(token.expiresAt) > now,
  );
}

const publicCheckFields = ["status", "paidAt", "paidVia", "amount", "transferReportedAt",
  "paymentGroupId", "paymentGroupPayerCheckId", "groupPaymentShareUntil", "groupPaymentShareLabel"];

function guestSessionView(sessionId, session, checkId, orders) {
  const ownOrders = orders.filter((order) => order.sessionId === sessionId && order.checkId === checkId);
  const check = session.checks?.[checkId] || { status: "open" };
  const safeCheck = Object.fromEntries(publicCheckFields.filter((key) => key in check).map((key) => [key, check[key]]));
  return {
    id: sessionId,
    table: session.table,
    status: session.status,
    waiterCalledAt: session.waiterCalledAt || null,
    updatedAt: session.updatedAt || null,
    closedAt: session.closedAt || null,
    totalBill: ownOrders.filter((order) => order.status !== "cancelled")
      .reduce((sum, order) => sum + Number(order.total || 0), 0),
    orderIds: ownOrders.map((order) => order.id),
    checks: { [checkId]: safeCheck },
  };
}

// Firestore Timestamp JSON differs from browser Timestamp. Use one wire format.
function toWire(value) {
  if (value === null || value === undefined) return value;
  if (value instanceof Date) return value.toISOString();
  if (typeof value.toDate === "function") return value.toDate().toISOString();
  if (Array.isArray(value)) return value.map(toWire);
  if (typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, toWire(entry)]));
  return value;
}

module.exports = { canReadGuestCheck, guestSessionView, toWire };
