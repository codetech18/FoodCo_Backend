const expectedInterval = (cycle) => cycle === "yearly" ? "annually" : "monthly";

const planMatchesCheckout = (plan, config) =>
  plan?.plan_code === config.planCode &&
  Number(plan.amount) === config.amountNaira * 100 &&
  plan.interval === expectedInterval(config.billingCycle) &&
  String(plan.currency || "NGN").toUpperCase() === "NGN";

const isSuccessfulSubscriptionCharge = (eventName, data) => {
  if (eventName === "charge.success") return data?.status === "success";
  return eventName === "invoice.update" &&
    data?.paid === true &&
    data?.status === "success" &&
    data?.transaction?.status === "success";
};

module.exports = { planMatchesCheckout, isSuccessfulSubscriptionCharge };
