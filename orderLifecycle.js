const isServiceFinished = (order) => ["served", "completed"].includes(order.status);

const statusAfterServing = (order) =>
  order.paymentStatus === "paid" ? "completed" : "served";

const canClosePaidTable = (orders) =>
  orders.length > 0 &&
  orders.some((order) => order.status !== "cancelled") &&
  orders.every((order) =>
    order.status === "cancelled" ||
    (isServiceFinished(order) && order.paymentStatus === "paid"),
  );

module.exports = { canClosePaidTable, statusAfterServing };
