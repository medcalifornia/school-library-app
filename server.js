const sql = require("mssql");
const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const twilio = require("twilio");
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,
    trustServerCertificate: false
  }
};
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 8080;

// ---------- Simple JSON storage (persisted in /home) ----------
const DATA_DIR = "/home/data";
const USERS_FILE = path.join(DATA_DIR, "users.json");
const READINGS_FILE = path.join(DATA_DIR, "readings.json");

function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
  if (!fs.existsSync(READINGS_FILE)) fs.writeFileSync(READINGS_FILE, JSON.stringify([]));
}
ensureDataFiles();

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ---------- Twilio ----------
const hasTwilio =
  process.env.TWILIO_ACCOUNT_SID &&
  process.env.TWILIO_AUTH_TOKEN &&
  process.env.TWILIO_VERIFY_SERVICE_SID;

const client = hasTwilio
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;

// ---------- Helpers ----------
function normalizePhone(phone) {
  if (!phone) return "";
  let p = String(phone).trim();
  // if user typed 1562..., convert to +1562...
  if (!p.startsWith("+")) p = "+" + p;
  return p;
}

// ---------- Routes ----------
app.get("/health", (req, res) => res.json({ status: "OK" }));

// Register
app.post("/api/register", async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const users = readJson(USERS_FILE);
  const p = normalizePhone(phone);
  const e = String(email).trim().toLowerCase();

  if (users.find(u => u.email === e)) return res.status(400).json({ error: "Email already used" });
  if (users.find(u => u.phone === p)) return res.status(400).json({ error: "Phone already used" });

  const hash = await bcrypt.hash(password, 10);

  users.push({
    id: Date.now().toString(),
    name: String(name).trim(),
    email: e,
    phone: p,
    passwordHash: hash,
    createdAt: new Date().toISOString(),
  });

  writeJson(USERS_FILE, users);
  res.json({ message: "Registered successfully" });
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const e = String(email || "").trim().toLowerCase();
  const users = readJson(USERS_FILE);
  const user = users.find(u => u.email === e);
  if (!user) return res.status(400).json({ error: "Invalid email or password" });

  const ok = await bcrypt.compare(password || "", user.passwordHash);
  if (!ok) return res.status(400).json({ error: "Invalid email or password" });

  // Very simple session: store userId in client localStorage
  res.json({ message: "Login OK", userId: user.id, name: user.name });
});

// Save reading (glucose / bp)
app.post("/api/readings", (req, res) => {
  const { userId, type, value, note } = req.body;
  if (!userId || !type || !value) return res.status(400).json({ error: "Missing fields" });

  const readings = readJson(READINGS_FILE);
  readings.push({
    id: Date.now().toString(),
    userId,
    type,
    value,
    note: note || "",
    ts: new Date().toISOString(),
  });
  writeJson(READINGS_FILE, readings);
  res.json({ message: "Saved" });
});

// Get readings for user
app.get("/api/readings/:userId", (req, res) => {
  const readings = readJson(READINGS_FILE);
  res.json(readings.filter(r => r.userId === req.params.userId));
});

// Chart summary for user (daily averages)
app.get("/api/chart/:userId", (req, res) => {
  const readings = readJson(READINGS_FILE).filter(r => r.userId === req.params.userId);

  // group by date
  const byDate = {};
  for (const r of readings) {
    const d = r.ts.slice(0, 10); // YYYY-MM-DD
    byDate[d] = byDate[d] || { glucose: [], bpSys: [], bpDia: [] };

    if (r.type === "glucose") byDate[d].glucose.push(Number(r.value));
    if (r.type === "bp") {
      // value like "118/76"
      const [s, di] = String(r.value).split("/").map(n => Number(n));
      if (!Number.isNaN(s)) byDate[d].bpSys.push(s);
      if (!Number.isNaN(di)) byDate[d].bpDia.push(di);
    }
  }

  const labels = Object.keys(byDate).sort();
  const glucoseAvg = labels.map(d => {
    const arr = byDate[d].glucose;
    if (!arr.length) return null;
    return Math.round(arr.reduce((a, b) => a + b, 0) / arr.length);
  });

  const sysAvg = labels.map(d => {
    const arr = byDate[d].bpSys;
    if (!arr.length) return null;
    return Math.round(arr.reduce((a, b) => a + b, 0) / arr.length);
  });

  const diaAvg = labels.map(d => {
    const arr = byDate[d].bpDia;
    if (!arr.length) return null;
    return Math.round(arr.reduce((a, b) => a + b, 0) / arr.length);
  });

  res.json({ labels, glucoseAvg, sysAvg, diaAvg });
});

// ---------- Forgot password (SMS Code) ----------
app.post("/api/forgot-password", async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  if (!phone) return res.status(400).json({ error: "Phone required" });
  if (!hasTwilio) return res.status(500).json({ error: "Twilio not configured on server" });

  // only allow reset if phone exists
  const users = readJson(USERS_FILE);
  const user = users.find(u => u.phone === phone);
  if (!user) return res.status(400).json({ error: "Phone not found" });

  try {
    await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({ to: phone, channel: "sms" });

    res.json({ message: "Code sent" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/verify-reset-code", async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const code = String(req.body.code || "").trim();
  if (!phone || !code) return res.status(400).json({ error: "Phone & code required" });
  if (!hasTwilio) return res.status(500).json({ error: "Twilio not configured on server" });

  try {
    const check = await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({ to: phone, code });

    if (check.status === "approved") return res.json({ message: "Verified" });
    return res.status(400).json({ error: "Invalid code" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/reset-password", async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const newPassword = String(req.body.newPassword || "");
  if (!phone || newPassword.length < 6) return res.status(400).json({ error: "Bad input" });

  const users = readJson(USERS_FILE);
  const idx = users.findIndex(u => u.phone === phone);
  if (idx === -1) return res.status(400).json({ error: "Phone not found" });

  users[idx].passwordHash = await bcrypt.hash(newPassword, 10);
  writeJson(USERS_FILE, users);
  res.json({ message: "Password updated" });
});

// default route
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log("Server running on port", PORT));
