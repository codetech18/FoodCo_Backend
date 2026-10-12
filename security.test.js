const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createHarness } = require("./testHarness");
const { canReadGuestCheck, guestSessionView } = require("./guestAccess");
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const checkA = `c_${"a".repeat(32)}`;
const checkB = `c_${"b".repeat(32)}`;
const secret = "a".repeat(64);

function fixture() {
  return {
    "users/owner": { role: "owner", restaurantId: "test" },
    "restaurants/test/profile/info": { ownerUid: "owner", suspended: false },
    "restaurants/test/tableSessions/s": { status: "open", table: "1", orderIds: ["a", "b"], totalBill: 3000,
      checks: { [checkA]: { status: "open", secretHash: hash(secret) }, [checkB]: { status: "open", secretHash: hash("b".repeat(64)) } },
      accessTokens: [{ hash: hash("table-token"), expiresAt: Date.now() + 60000 }] },
    "restaurants/test/orders/a": { sessionId: "s", checkId: checkA, status: "pending", total: 1000, email: "alice@example.invalid", items: [] },
    "restaurants/test/orders/b": { sessionId: "s", checkId: checkB, status: "pending", total: 2000, email: "bob@example.invalid", items: [] },
  };
}

test("incorrect OTP attempts commit, then the sixth guess is locked out", async () => {
  const h = createHarness();
  const email = "owner@example.invalid";
  const key = `emailOtps/password_reset_${hash(email)}`;
  h.records.set(key, { codeHash: "wrong", attempts: 0, expiresAt: new Date(Date.now() + 600000) });
  const statuses = [];
  for (let i = 0; i < 6; i++) statuses.push((await h.invoke("/auth/verify-otp", { email, purpose: "password_reset", code: "000000" })).status);
  assert.deepEqual(statuses, [400, 400, 400, 400, 400, 429]);
  assert.equal(h.records.get(key).attempts, 5);
});

test("guest data contains only their own check and no security hashes", async () => {
  const h = createHarness(fixture());
  const response = await h.invoke("/guest-session", { restaurantId: "test", sessionId: "s", checkId: checkA, checkSecret: secret, accessToken: "table-token", orderId: "a" });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.session.orderIds, ["a"]);
  assert.equal(response.body.session.totalBill, 1000);
  assert.deepEqual(Object.keys(response.body.session.checks), [checkA]);
  assert.equal(JSON.stringify(response.body).includes("bob@example.invalid"), false);
  assert.equal(JSON.stringify(response.body).includes("secretHash"), false);
  assert.equal(JSON.stringify(response.body).includes("accessTokens"), false);
});

test("another guest's order or check cannot be read with the first guest's credentials", async () => {
  const h = createHarness(fixture());
  const credentials = { restaurantId: "test", sessionId: "s", checkId: checkA, checkSecret: secret, accessToken: "table-token" };
  assert.equal((await h.invoke("/guest-session", { ...credentials, orderId: "b" })).status, 404);
  assert.equal((await h.invoke("/guest-session", { ...credentials, checkId: checkB })).status, 403);
  assert.equal((await h.invoke("/guest-session", { ...credentials, restaurantId: "other" })).status, 403);
});

test("private read capability survives token expiry, while staff checks are never public", () => {
  const session = fixture()["restaurants/test/tableSessions/s"];
  session.accessTokens = [];
  assert.equal(canReadGuestCheck(session, checkA, secret, "expired"), true);
  session.checks[checkA] = { status: "open" };
  assert.equal(canReadGuestCheck(session, checkA, secret, "expired"), false);
  assert.equal(guestSessionView("s", session, checkA, []).totalBill, 0);
});

test("moving an order preserves the target private check's metadata", async () => {
  const h = createHarness(fixture());
  const originalHash = h.records.get("restaurants/test/tableSessions/s").checks[checkB].secretHash;
  assert.equal((await h.invoke("/move-order-check", { restaurantId: "test", sessionId: "s", orderId: "a", targetCheckId: checkB })).status, 200);
  assert.equal(h.records.get("restaurants/test/tableSessions/s").checks[checkB].secretHash, originalHash);
  assert.equal(h.authCalls[0].revoked, true);
});

test("revoked tokens cannot invoke staff routes", async () => {
  const h = createHarness(fixture());
  assert.equal((await h.invoke("/move-order-check", { restaurantId: "test" }, { uid: "revoked" })).status, 401);
});


test("waiter calls require a matching private check and a current table token", async () => {
  const h = createHarness(fixture());
  const credentials = { restaurantId: "test", sessionId: "s", checkId: checkA, checkSecret: secret, accessToken: "table-token" };
  assert.equal((await h.invoke("/call-waiter", { restaurantId: "test", sessionId: "s" })).status, 403);
  assert.equal((await h.invoke("/call-waiter", { ...credentials, checkId: checkB })).status, 403);
  assert.equal((await h.invoke("/call-waiter", { ...credentials, accessToken: "expired" })).status, 403);
  assert.equal(h.records.get("restaurants/test/tableSessions/s").waiterCalledAt, undefined);
  assert.equal((await h.invoke("/call-waiter", credentials)).status, 200);
  assert.ok(h.records.get("restaurants/test/tableSessions/s").waiterCalledAt);
});

test("guest bill endpoints accept private credentials only in POST bodies", async () => {
  const h = createHarness(fixture());
  const credentials = { restaurantId: "test", sessionId: "s", orderId: "a", checkSecret: secret, accessToken: "table-token" };
  assert.equal((await h.invoke("/shared-table-bills", credentials)).status, 200);
  assert.equal((await h.invoke("/shared-table-bills", { ...credentials, orderId: "b" })).status, 403);
  assert.equal((await h.invoke("/transfer-details", credentials)).status, 409);
  const session = h.records.get("restaurants/test/tableSessions/s");
  session.checks[checkA].status = "awaiting_payment";
  h.records.set("restaurants/test/profile/private", { bankName: "Demo Bank", accountName: "Demo Venue", accountNumber: "0000000000" });
  assert.equal((await h.invoke("/transfer-details", credentials)).status, 200);
});
