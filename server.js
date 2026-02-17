const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

let twilioClient = null;
try {
  const twilio = require("twilio");
  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
    twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  }
} catch {}

const app = express();
app.use(express.json());

// ===== Config =====
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

const TWILIO_FROM_NUMBER = process.env.TWILIO_FROM_NUMBER || ""; // +1xxxx
const VERIFY_CHANNEL = "sms"; // fixed to sms here

// ===== In-memory DB (demo only) =====
const usersByEmail = new Map(); // email -> user
const readingsByUserId = new Map(); // uid -> readings[]

function newId() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function makeCode() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6 digits
}

function nowIso() {
  return new Date().toISOString();
}

// ===== Auth middleware =====
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ===== Health check (use in Azure health check path) =====
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "API is healthy" });
});

// ===== Send verification by SMS =====
async function sendSms(to, text) {
  if (!twilioClient) throw new Error("Twilio client not configured");
  if (!TWILIO_FROM_NUMBER) throw new Error("TWILIO_FROM_NUMBER missing");
  await twilioClient.messages.create({ from: TWILIO_FROM_NUMBER, to, body: text });
}

// ===== Register =====
app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const phone = String(req.body.phone || "").trim(); // must be +1...
    const password = String(req.body.password || "");

    if (!name) return res.status(400).json({ error: "Name required" });
    if (!email) return res.status(400).json({ error: "Email required" });
    if (!phone || !phone.startsWith("+")) {
      return res.status(400).json({ error: 'Phone required in format like "+15625551234"' });
    }
    if (password.length < 6) return res.status(400).json({ error: "Password must be 6+ chars" });

    if (usersByEmail.has(email)) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const passHash = await bcrypt.hash(password, 10);
    const user = {
      id: newId(),
      name,
      email,
      phone,
      passHash,
      verified: false,
      verifyCode: null,
      verifyExpiresAt: null,
      createdAt: nowIso() // auto date/time
    };

    // create code
    const code = makeCode();
    user.verifyCode = code;
    user.verifyExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    usersByEmail.set(email, user);

    // send SMS
    const msg = `Your verification code is: ${code} (valid 10 min)`;
    try {
      await sendSms(user.phone, msg);
      return res.json({
        ok: true,
        message: "Registered. SMS code sent.",
        createdAt: user.createdAt
      });
    } catch (e) {
      // user exists but SMS failed
      return res.json({
        ok: true,
        message: "Registered, but SMS failed. Check Twilio settings.",
        providerError: String(e.message || e),
        createdAt: user.createdAt
      });
    }
  } catch (e) {
    return res.status(500).json({ error: "Server error", details: String(e.message || e) });
  }
});

// ===== Verify =====
app.post("/api/verify", (req, res) => {
  const email = normalizeEmail(req.body.email);
  const code = String(req.body.code || "").trim();

  const user = usersByEmail.get(email);
  if (!user) return res.status(404).json({ error: "User not found" });

  if (!user.verifyCode || !user.verifyExpiresAt) {
    return res.status(400).json({ error: "No verification pending. Register again." });
  }

  if (Date.now() > user.verifyExpiresAt) {
    return res.status(400).json({ error: "Code expired. Register again to get a new code." });
  }

  if (code !== user.verifyCode) {
    return res.status(400).json({ error: "Invalid code" });
  }

  user.verified = true;
  user.verifyCode = null;
  user.verifyExpiresAt = null;

  return res.json({ ok: true, message: "Verified. You can login now." });
});

// ===== Login =====
app.post("/api/login", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  const user = usersByEmail.get(email);
  if (!user) return res.status(404).json({ error: "User not found" });

  const ok = await bcrypt.compare(password, user.passHash);
  if (!ok) return res.status(401).json({ error: "Invalid email or password" });

  if (!user.verified) return res.status(403).json({ error: "Not verified yet" });

  const token = jwt.sign(
    { uid: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  return res.json({ ok: true, token, user: { name: user.name, email: user.email } });
});

// ===== Add reading (Glucose + BP) with auto date/time =====
app.post("/api/readings", auth, (req, res) => {
  const glucose = req.body.glucose === "" || req.body.glucose == null ? null : Number(req.body.glucose);
  const systolic = req.body.systolic === "" || req.body.systolic == null ? null : Number(req.body.systolic);
  const diastolic = req.body.diastolic === "" || req.body.diastolic == null ? null : Number(req.body.diastolic);
  const note = String(req.body.note || "").trim();

  // Validate: at least one of glucose or BP must exist
  const hasGlucose = Number.isFinite(glucose) && glucose > 0;
  const hasBP = Number.isFinite(systolic) && systolic > 0 && Number.isFinite(diastolic) && diastolic > 0;
  if (!hasGlucose && !hasBP) {
    return res.status(400).json({
      error: "Enter glucose and/or blood pressure (systolic + diastolic)."
    });
  }

  const item = {
    id: newId(),
    createdAt: nowIso(), // auto date/time here
    glucose: hasGlucose ? glucose : null,
    bloodPressure: hasBP ? { systolic, diastolic } : null,
    note
  };

  const uid = req.user.uid;
  if (!readingsByUserId.has(uid)) readingsByUserId.set(uid, []);
  readingsByUserId.get(uid).unshift(item);

  return res.json({ ok: true, item });
});

// ===== List readings =====
app.get("/api/readings", auth, (req, res) => {
  const uid = req.user.uid;
  const list = readingsByUserId.get(uid) || [];
  res.json({ ok: true, list });
});

// ===== Serve public pages =====
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.redirect("/register.html");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});