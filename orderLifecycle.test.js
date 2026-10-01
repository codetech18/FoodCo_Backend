const { test } = require("node:test");
const assert = require("node:assert/strict");
const { canClosePaidTable, statusAfterServing } = require("./orderLifecycle");

test("serving cannot complete an unpaid order", () => {
  assert.equal(statusAfterServing({ status: "ready" }), "served");
  assert.equal(statusAfterServing({ status: "ready", paymentStatus: "unpaid" }), "served");
  assert.equal(statusAfterServing({ status: "ready", paymentStatus: "paid" }), "completed");
});

test("does not release an empty or entirely cancelled table as paid", () => {
  assert.equal(canClosePaidTable([]), false);
  assert.equal(canClosePaidTable([{ status: "cancelled" }]), false);
});

test("requires service and payment for every active order", () => {
  assert.equal(canClosePaidTable([{ status: "ready", paymentStatus: "paid" }]), false);
  assert.equal(canClosePaidTable([{ status: "served" }]), false);
  assert.equal(canClosePaidTable([{ status: "completed" }]), false);
  assert.equal(canClosePaidTable([
    { status: "completed", paymentStatus: "paid" },
    { status: "served", paymentStatus: "unpaid" },
  ]), false);
  assert.equal(canClosePaidTable([
    { status: "completed", paymentStatus: "paid" },
    { status: "served", paymentStatus: "paid" },
    { status: "cancelled" },
  ]), true);
});
