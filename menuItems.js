const itemId = (value) => /^[a-zA-Z0-9_-]{1,120}$/.test(String(value || ""));

async function verifiedMenuItems(tx, db, restaurantId, items) {
  let snapshots;
  if (items.every((item) => itemId(item.id))) {
    snapshots = await Promise.all([...new Set(items.map((item) => item.id))]
      .map((id) => tx.get(db.doc(`restaurants/${restaurantId}/menu/${id}`))));
  } else {
    // Compatibility for orders created before menu IDs were retained. Names
    // must match exactly one dish; duplicate names are never guessed.
    snapshots = (await tx.get(db.collection(`restaurants/${restaurantId}/menu`))).docs;
  }
  const entries = snapshots.filter((snap) => snap.exists !== false).map((snap) => ({ id: snap.id, ...snap.data() }));
  return items.map((item) => {
    const matches = item.id ? entries.filter((entry) => entry.id === item.id)
      : entries.filter((entry) => entry.name.trim() === String(item.name || "").trim());
    if (matches.length !== 1 || matches[0].available === false) {
      throw Object.assign(new Error(`${item.name || "This dish"} has changed or is unavailable. Please select it again from the menu.`), { statusCode: 409 });
    }
    const menu = matches[0];
    const price = Number(menu.price);
    if (!Number.isFinite(price) || price < 0 || !Number.isSafeInteger(Math.round(price * 100)) || Math.abs(price * 100 - Math.round(price * 100)) > 0.000001) {
      throw Object.assign(new Error("A dish price needs staff attention. Use a valid amount with at most two decimal places."), { statusCode: 409 });
    }
    return { id: menu.id, name: String(menu.name), price, qty: Number(item.qty), station: menu.station === "bar" ? "bar" : "kitchen" };
  });
}

module.exports = { verifiedMenuItems };
