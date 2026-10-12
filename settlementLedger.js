const revenueField = (method) => ({ cash: "cashRevenue", pos: "posRevenue", transfer: "transferRevenue", online: "onlineRevenue" })[method] || "otherRevenue";
const emptyTotals = () => ({ totalRevenue: 0, cashRevenue: 0, posRevenue: 0, transferRevenue: 0, onlineRevenue: 0, otherRevenue: 0, settledOrders: 0, settledTables: 0 });

function summarizePayments(settlements, legacyPaidOrders, closedSessions) {
  const totals = emptyTotals();
  const coveredOrders = new Set();
  for (const payment of settlements) {
    totals.totalRevenue += Number(payment.amount || 0);
    totals[revenueField(payment.paidVia)] += Number(payment.amount || 0);
    totals.settledOrders += (payment.orderIds || []).length;
    for (const id of payment.orderIds || []) coveredOrders.add(id);
  }
  // Older collections have per-order paidAt/paidVia, even where the mutable
  // fallback check stores only its last payment. Never count ledger orders twice.
  for (const order of legacyPaidOrders) {
    if (coveredOrders.has(order.id) || order.paymentStatus !== "paid" || order.status === "cancelled") continue;
    totals.totalRevenue += Number(order.total || 0);
    totals[revenueField(order.paidVia)] += Number(order.total || 0);
    totals.settledOrders += 1;
  }
  totals.settledTables = closedSessions.filter((session) => session.status === "paid").length;
  return totals;
}

function pendingTransferTotals(session, orders) {
  const pending = new Set(Object.entries(session.checks || {})
    .filter(([, state]) => state.status === "transfer_reported").map(([id]) => id));
  if (!session.checks?.legacy && session.status === "transfer_reported") pending.add("legacy");
  const balances = new Map();
  for (const order of orders) {
    const checkId = order.checkId || "legacy";
    if (pending.has(checkId) && order.status !== "cancelled" && order.paymentStatus !== "paid") {
      balances.set(checkId, (balances.get(checkId) || 0) + Number(order.total || 0));
    }
  }
  return { count: balances.size, total: [...balances.values()].reduce((sum, value) => sum + value, 0) };
}

module.exports = { summarizePayments, pendingTransferTotals };
