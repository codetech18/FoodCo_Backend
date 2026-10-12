// Executes actual Express handlers against an isolated transactional store.
// Credentials, outgoing requests and server listeners are deliberately mocked.
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

function createHarness(initial = {}) {
  const records = new Map(Object.entries(initial));
  const routes = new Map();
  let sequence = 0;
  const snapshot = (ref) => ({ ref, id: ref.id, exists: records.has(ref.path), data: () => structuredClone(records.get(ref.path)) });
  const apply = (ref, fields, merge) => {
    const next = merge ? structuredClone(records.get(ref.path) || {}) : {};
    for (const [key, value] of Object.entries(fields)) {
      if (value?.operation === "increment") next[key] = Number(next[key] || 0) + value.amount;
      else if (value?.operation === "union") next[key] = [...new Set([...(next[key] || []), ...value.values])];
      else if (value?.operation === "delete") delete next[key];
      else next[key] = structuredClone(value);
    }
    records.set(ref.path, next);
  };
  const doc = (location) => ({
    path: location, id: location.split("/").at(-1),
    get: async () => snapshot(doc(location)),
    set: async (fields, options) => apply(doc(location), fields, Boolean(options?.merge)),
    update: async (fields) => apply(doc(location), fields, true),
    delete: async () => records.delete(location),
  });
  function query(location, group = false, filters = [], maximum = Infinity, sort = null) {
    return {
      path: location,
      where: (field, operator, value) => query(location, group, [...filters, [field, operator, value]], maximum, sort),
      limit: (value) => query(location, group, filters, value, sort),
      orderBy: (field, direction) => query(location, group, filters, maximum, [field, direction]),
      doc: (id = `generated_${++sequence}`) => doc(`${location}/${id}`),
      get: async () => {
        let keys = [...records.keys()].filter((key) => group
          ? key.split("/").at(-2) === location
          : key.startsWith(`${location}/`) && !key.slice(location.length + 1).includes("/"));
        keys = keys.filter((key) => filters.every(([field, operator, value]) => {
          const actual = records.get(key)[field];
          if (operator === "==") return actual === value;
          if (operator === ">=") return actual >= value;
          if (operator === "<") return actual < value;
          if (operator === "<=") return actual <= value;
          if (operator === "in") return value.includes(actual);
          if (operator === ">") return actual > value;
          throw new Error(`Unsupported test query: ${operator}`);
        }));
        if (sort) keys.sort((a, b) => (records.get(a)[sort[0]] > records.get(b)[sort[0]] ? 1 : -1) * (sort[1] === "desc" ? -1 : 1));
        const docs = keys.slice(0, maximum).map((key) => snapshot(doc(key)));
        return { docs, empty: !docs.length, size: docs.length, forEach: (callback) => docs.forEach(callback) };
      },
    };
  }
  const db = {
    doc, collection: (location) => query(location), collectionGroup: (name) => query(name, true),
    getAll: (...refs) => Promise.all(refs.map((ref) => ref.get())),
    async runTransaction(callback) {
      for (let attempt = 0; attempt < 5; attempt++) {
        const writes = [];
        const reads = new Map();
        const tx = {
          get: async (ref) => {
            if (writes.length) throw new Error("Transaction read after write");
            if (ref.where) return ref.get();
            reads.set(ref.path, JSON.stringify(records.get(ref.path)));
            return ref.get();
          },
          getAll: async (...refs) => Promise.all(refs.map((ref) => tx.get(ref))),
          update: (ref, fields) => writes.push(() => apply(ref, fields, true)),
          set: (ref, fields, options) => writes.push(() => apply(ref, fields, Boolean(options?.merge))),
          create: (ref, fields) => writes.push(() => { if (records.has(ref.path)) throw new Error("Document exists"); apply(ref, fields, false); }),
          delete: (ref) => writes.push(() => records.delete(ref.path)),
        };
        const result = await callback(tx);
        if (db.beforeCommit) { const hook = db.beforeCommit; db.beforeCommit = null; await hook(); }
        if ([...reads].some(([key, value]) => JSON.stringify(records.get(key)) !== value)) continue;
        writes.forEach((write) => write());
        return result;
      }
      throw new Error("Transaction retry limit");
    },
    batch() {
      const writes = [];
      return { set: (ref, fields, options) => writes.push(() => apply(ref, fields, Boolean(options?.merge))),
        update: (ref, fields) => writes.push(() => apply(ref, fields, true)), commit: async () => writes.forEach((write) => write()) };
    },
  };
  const FieldValue = {
    increment: (amount) => ({ operation: "increment", amount }),
    arrayUnion: (...values) => ({ operation: "union", values }),
    serverTimestamp: () => new Date(), delete: () => ({ operation: "delete" }),
  };
  const authCalls = [];
  const auth = {
    verifyIdToken: async (token, revoked) => { authCalls.push({ token, revoked }); if (token === "revoked") throw Error("Revoked"); return { uid: token, email: `${token}@example.invalid`, email_verified: true }; },
    getUserByEmail: async () => ({ uid: "owner" }), getUser: async (uid) => ({ uid }),
    updateUser: async () => ({}), revokeRefreshTokens: async () => ({}),
  };
  const app = { set() {}, use() {}, listen() {} };
  for (const method of ["get", "post", "delete"]) app[method] = (location, ...handlers) => routes.set(`${method.toUpperCase()} ${location}`, handlers);
  const express = () => app;
  express.json = express.urlencoded = () => (_req, _res, next) => next();
  const admin = { initializeApp() {}, credential: { cert() {} }, auth: () => auth, firestore: Object.assign(() => db, { FieldValue }) };
  const mocks = { dotenv: { config() {} }, express, cors: () => () => {}, crypto: require("node:crypto"),
    resend: { Resend: class { emails = { send: async () => ({}) }; } }, "firebase-admin": admin,
    "firebase-admin/app": { initializeApp() {}, cert() {} }, "firebase-admin/auth": { getAuth: () => auth },
    "firebase-admin/firestore": { getFirestore: () => db, FieldValue } };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "app.js"), "utf8"), {
    require: (name) => mocks[name] || require(name.startsWith(".") ? path.join(__dirname, name) : name),
    process: { env: { FIREBASE_SERVICE_ACCOUNT: "{}" } }, console: { log() {}, warn() {}, error() {} },
    setInterval: () => ({ unref() {} }), clearInterval() {}, Date, Buffer, URL, URLSearchParams,
    fetch: async () => { throw Error("Network disabled in tests"); },
  });
  async function invoke(location, body = {}, options = {}) {
    const method = options.method || "POST";
    const req = { method, path: location, ip: "127.0.0.1", body, query: options.query || {},
      headers: { authorization: `Bearer ${options.uid || "owner"}` }, firebaseUser: { uid: options.uid || "owner" } };
    const res = { statusCode: 200, headers: {}, setHeader(key, value) { this.headers[key] = value; },
      status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; } };
    const handlers = routes.get(`${method} ${location}`);
    if (!handlers) throw Error(`Unknown route ${method} ${location}`);
    const next = async (index) => handlers[index]?.(req, res, () => next(index + 1));
    await next(0);
    return { status: res.statusCode, body: res.body, headers: res.headers };
  }
  return { records, db, invoke, authCalls };
}

module.exports = { createHarness };
