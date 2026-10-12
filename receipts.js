const escape = (value) => String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

function receiptsForSettlement(payment) {
  const byEmail = new Map();
  for (const order of payment.receiptOrders || []) {
    const email = String(order.email || "").trim().toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(email)) continue;
    if (!byEmail.has(email)) byEmail.set(email, []);
    byEmail.get(email).push(order);
  }
  return [...byEmail].map(([email, orders]) => ({
    email, orders, total: orders.reduce((sum, order) => sum + Number(order.total || 0), 0),
  }));
}

function receiptHtml(payment, receipt) {
  const rows = receipt.orders.flatMap((order) => order.items || []).map((item) =>
    `<tr><td style="padding:8px">${Number(item.qty)} × ${escape(item.name)}</td><td style="padding:8px;text-align:right">₦${(Number(item.price) * Number(item.qty)).toLocaleString("en-NG")}</td></tr>`).join("");
  return `<div style="font-family:Arial,sans-serif;max-width:480px;padding:24px;color:#291f1a"><h1>${escape(payment.receipt.restaurantName)}</h1><p>Table ${escape(payment.table)} · Your receipt</p><table style="width:100%">${rows}</table><p><strong>Total: ₦${receipt.total.toLocaleString("en-NG")}</strong></p><p>Payment: ${escape(payment.paidVia)}</p><p>Thank you for dining with us.</p></div>`;
}

module.exports = { receiptsForSettlement, receiptHtml };
