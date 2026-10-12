const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHarness } = require("./testHarness");
const { receiptsForSettlement } = require("./receipts");

function fixture() {
  return {
    "users/owner": { role: "owner", restaurantId: "test" },
    "restaurants/test/profile/info": { ownerUid: "owner", name: "Test venue", suspended: false },
    "restaurants/test/tableSessions/s": { status: "open", table: "1", orderIds: ["a", "b"], totalBill: 3000, amountPaid: 0, updatedAt: new Date(Date.now() - 5 * 3600000) },
    "restaurants/test/tables/1": { currentSessionId: "s", token: "qr" },
    "restaurants/test/orders/a": { customerName: "Alice", email: "alice@example.invalid", status: "served", total: 1000, items: [], sessionId: "s" },
    "restaurants/test/orders/b": { customerName: "Bob", email: "bob@example.invalid", status: "served", total: 2000, items: [], sessionId: "s" },
  };
}
const summary = (h) => [...h.records.entries()].find(([key]) => /dailySummaries\/\d/.test(key))?.[1];

test("partial legacy payments retain cash/POS amounts and counts after repeated rebuilds", async () => {
  const h = createHarness(fixture());
  const first = await h.invoke("/settle-checks", { restaurantId: "test", sessionId: "s", orderIds: ["a"], paidVia: "cash" });
  const second = await h.invoke("/settle-checks", { restaurantId: "test", sessionId: "s", orderIds: ["b"], paidVia: "pos" });
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal([...h.records.keys()].filter((key) => key.includes("/settlements/")).length, 2);
  for (let i = 0; i < 2; i++) {
    assert.equal((await h.invoke("/rebuild-daily-summaries", { restaurantId: "test", days: 1 })).status, 200);
    assert.equal(summary(h).totalRevenue, 3000);
    assert.equal(summary(h).cashRevenue, 1000);
    assert.equal(summary(h).posRevenue, 2000);
    assert.equal(summary(h).settledOrders, 2);
  }
});

test("retrying the same settlement returns its receipt without collecting twice", async () => {
  const h = createHarness(fixture());
  const payload = { restaurantId: "test", sessionId: "s", orderIds: ["a"], paidVia: "cash" };
  const first = await h.invoke("/settle-checks", payload);
  const second = await h.invoke("/settle-checks", payload);
  assert.equal(second.status, 200);
  assert.equal(second.body.settlementId, first.body.settlementId);
  assert.equal(summary(h).totalRevenue, 1000);
});

test("historical payments without ledger events rebuild from each paid order", async () => {
  const data = fixture();
  data["restaurants/test/orders/a"] = { ...data["restaurants/test/orders/a"], paymentStatus: "paid", paidVia: "cash", paidAt: new Date() };
  data["restaurants/test/orders/b"] = { ...data["restaurants/test/orders/b"], paymentStatus: "paid", paidVia: "pos", paidAt: new Date() };
  data["restaurants/test/tableSessions/s"].checks = { legacy: { status: "paid", amount: 2000, paidVia: "pos", paidAt: new Date() } };
  const h = createHarness(data);
  assert.equal((await h.invoke("/rebuild-daily-summaries", { restaurantId: "test", days: 1 })).status, 200);
  assert.equal(summary(h).totalRevenue, 3000);
  assert.equal(summary(h).cashRevenue, 1000);
});

test("a concurrent collection causes the rebuild transaction to retry", async () => {
  const h = createHarness(fixture());
  await h.invoke("/settle-checks", { restaurantId: "test", sessionId: "s", orderIds: ["a"], paidVia: "cash" });
  h.db.beforeCommit = () => {
    h.records.set("restaurants/test/orders/b", { ...h.records.get("restaurants/test/orders/b"), paymentStatus: "paid", paidAt: new Date(), paidVia: "pos" });
    const entry = [...h.records.entries()].find(([key]) => key.includes("/dailySummaries/"));
    h.records.set(entry[0], { ...entry[1], totalRevenue: 3000, posRevenue: 2000 });
  };
  assert.equal((await h.invoke("/rebuild-daily-summaries", { restaurantId: "test", days: 1 })).status, 200);
  assert.equal(summary(h).totalRevenue, 3000);
});

test("rebuild leaves reconciled days unchanged", async () => {
  const h = createHarness(fixture());
  await h.invoke("/settle-checks", { restaurantId: "test", sessionId: "s", orderIds: ["a"], paidVia: "cash" });
  const [key, value] = [...h.records.entries()].find(([key]) => key.includes("/dailySummaries/"));
  h.records.set(key, { ...value, reconciledAt: new Date() });
  const response = await h.invoke("/rebuild-daily-summaries", { restaurantId: "test", days: 1 });
  assert.equal(response.body.lockedDaysSkipped, 1);
  assert.equal(summary(h).totalRevenue, 1000);
});

test("an idle visit with unpaid food remains active and settleable after a QR scan", async () => {
  const h = createHarness(fixture());
  const scan = await h.invoke("/open-table-session", { restaurantId: "test", table: "1", token: "qr" });
  assert.equal(scan.status, 200);
  assert.equal(scan.body.sessionId, "s");
  assert.equal(h.records.get("restaurants/test/tableSessions/s").status, "open");
  assert.equal((await h.invoke("/settle-checks", { restaurantId: "test", sessionId: "s", orderIds: ["a", "b"], paidVia: "cash" })).status, 200);
});

test("pending transfers count reported unpaid checks, excluding other bills and paid orders", async () => {
  const data = fixture();
  data["restaurants/test/tableSessions/s"].checks = { c_reported: { status: "transfer_reported" }, c_other: { status: "open" } };
  data["restaurants/test/orders/a"].checkId = "c_reported";
  data["restaurants/test/orders/b"].checkId = "c_other";
  const h = createHarness(data);
  const response = await h.invoke("/pending-transfers", {}, { method: "GET", query: { restaurantId: "test" } });
  assert.equal(response.status, 200);
  assert.equal(response.body.count, 1);
  assert.equal(response.body.total, 1000);
});

test("each emailed receipt contains only that recipient's recorded orders", () => {
  const receipts = receiptsForSettlement({ receiptOrders: [
    { email: "alice@example.invalid", customerName: "Alice", total: 1000, items: [{ name: "Alice dish" }] },
    { email: "bob@example.invalid", customerName: "Bob", total: 2000, items: [{ name: "Bob dish" }] },
  ] });
  assert.equal(receipts.length, 2);
  assert.equal(receipts[0].total, 1000);
  assert.equal(receipts[0].orders.length, 1);
  assert.equal(receipts[1].total, 2000);
});

test("named kitchen staff cannot collect money", async () => {
  const data = fixture();
  data["users/cook"] = { restaurantId: "test", role: "kitchen", accountType: "individual_staff" };
  const h = createHarness(data);
  assert.equal((await h.invoke("/settle-checks", { restaurantId: "test", sessionId: "s", orderIds: ["a"], paidVia: "cash" }, { uid: "cook" })).status, 403);
  assert.equal(h.records.get("restaurants/test/orders/a").paymentStatus, undefined);
});

test("incomplete older payment dates cannot silently reduce an existing summary", async () => {
  const h = createHarness(fixture());
  const key = new Intl.DateTimeFormat("en-CA", { timeZone: "Africa/Lagos" }).format(new Date());
  h.records.set(`restaurants/test/dailySummaries/${key}`, { dateKey: key, totalRevenue: 9000 });
  const result = await h.invoke("/rebuild-daily-summaries", { restaurantId: "test", days: 1 });
  assert.equal(result.status, 409);
  assert.equal(summary(h).totalRevenue, 9000);
});
