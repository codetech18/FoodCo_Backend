const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createHarness } = require("./testHarness");
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const checkId = `c_${"a".repeat(32)}`;
const checkSecret = "a".repeat(64);

function setup() {
  return createHarness({
    "restaurants/test/profile/info": { ownerUid: "owner", suspended: false },
    "restaurants/test/tableSessions/s": { status: "open", table: "1", orderIds: [], totalBill: 0, checks: {}, accessTokens: [{ hash: hash("token"), expiresAt: Date.now() + 60000 }] },
    "restaurants/test/menu/kitchen": { name: "Chicken", price: 1000, station: "kitchen", available: true },
    "restaurants/test/menu/bar": { name: "Chicken", price: 2000, station: "bar", available: true },
  });
}
const payload = { restaurantId: "test", sessionId: "s", accessToken: "token", checkId, checkSecret, customerName: "Guest", table: "1", requestId: "request_123456789", items: [{ id: "bar", name: "Chicken", price: 1, qty: 2 }] };

test("duplicate-name dishes retain identity, canonical price and routing", async () => {
  const h = setup();
  const result = await h.invoke("/place-order", payload);
  assert.equal(result.status, 200);
  const order = h.records.get(`restaurants/test/orders/${result.body.orderId}`);
  assert.equal(order.total, 4000);
  assert.equal(order.items[0].id, "bar");
  assert.equal(order.items[0].station, "bar");
});

test("lost-response retries create only one order and one bill increment", async () => {
  const h = setup();
  const first = await h.invoke("/place-order", payload);
  const second = await h.invoke("/place-order", payload);
  assert.equal(second.status, 200);
  assert.equal(second.body.orderId, first.body.orderId);
  assert.equal([...h.records.keys()].filter((key) => key.includes("/orders/")).length, 1);
  assert.equal(h.records.get("restaurants/test/tableSessions/s").totalBill, 4000);
});

test("reusing a request with another cart is rejected", async () => {
  const h = setup();
  await h.invoke("/place-order", payload);
  assert.equal((await h.invoke("/place-order", { ...payload, items: [{ ...payload.items[0], qty: 3 }] })).status, 409);
});

test("already issued table tokens cannot submit new orders after suspension", async () => {
  const h = setup();
  h.records.get("restaurants/test/profile/info").suspended = true;
  assert.equal((await h.invoke("/place-order", payload)).status, 403);
  assert.equal(h.records.get("restaurants/test/tableSessions/s").totalBill, 0);
});

test("legacy carts with an ambiguous dish name are rejected rather than guessed", async () => {
  const h = setup();
  const { id, ...legacy } = payload.items[0];
  assert.equal((await h.invoke("/place-order", { ...payload, items: [legacy] })).status, 409);
});

test("pausing service rejects new orders while an existing visit remains readable", async () => {
  const h = setup();
  h.records.get("restaurants/test/profile/info").servicePaused = true;
  assert.equal((await h.invoke("/place-order", payload)).status, 403);
});

test("currency totals use integer kobo rather than accumulated floating-point error", async () => {
  const h = setup();
  h.records.set("restaurants/test/menu/kitchen", { name: "Small", price: 0.1, available: true });
  h.records.set("restaurants/test/menu/bar", { name: "Other", price: 0.2, available: true });
  const result = await h.invoke("/place-order", { ...payload, items: [
    { id: "kitchen", name: "Small", price: 0.1, qty: 1 }, { id: "bar", name: "Other", price: 0.2, qty: 1 },
  ] });
  assert.equal(result.status, 200);
  assert.equal(result.body.total, 0.3);
});
