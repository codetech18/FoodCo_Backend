const test = require("node:test");
const assert = require("node:assert/strict");
const { planMatchesCheckout, isSuccessfulSubscriptionCharge } = require("./subscriptionBilling");

const config = { planCode: "PLN_core_yearly", amountNaira: 250000, billingCycle: "yearly" };

test("checkout requires the configured Paystack price, currency and interval", () => {
  const plan = { plan_code: config.planCode, amount: 25000000, currency: "NGN", interval: "annually" };
  assert.equal(planMatchesCheckout(plan, config), true);
  assert.equal(planMatchesCheckout({ ...plan, amount: 2500000 }, config), false);
  assert.equal(planMatchesCheckout({ ...plan, currency: "GHS" }, config), false);
  assert.equal(planMatchesCheckout({ ...plan, interval: "monthly" }, config), false);
  assert.equal(planMatchesCheckout({ ...plan, plan_code: "PLN_other" }, config), false);
});

test("only successful payment events may activate or renew access", () => {
  assert.equal(isSuccessfulSubscriptionCharge("subscription.create", { status: "active" }), false);
  assert.equal(isSuccessfulSubscriptionCharge("charge.success", { status: "success" }), true);
  assert.equal(isSuccessfulSubscriptionCharge("charge.success", { status: "failed" }), false);
  assert.equal(isSuccessfulSubscriptionCharge("invoice.update", {
    paid: true, status: "success", transaction: { status: "success" },
  }), true);
  assert.equal(isSuccessfulSubscriptionCharge("invoice.update", {
    paid: true, status: "success", transaction: { status: "failed" },
  }), false);
});
