const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 8080;

// ===== ENV =====
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_VERIFY_SERVICE_SID = process.env.TWILIO_VERIFY_SERVICE_SID;

const hasTwilioVerify =
  !!TWILIO_ACCOUNT_SID && !!TWILIO_AUTH_TOKEN && !!TWILIO_VERIFY_SERVICE_SID;

let twilioClient = null;
if (hasTwilioVerify) {
  twilioClient = require("twilio")(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
}

// ===== DB =====
const db = new sqlite3.Database(path.join(__dirname, "diabetes.sqlite"));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL,
      pass_hash TEXT NOT NULL,
      verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS readings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,              -- 'glucose' or 'bp'
      glucose_mgdl INTEGER,            -- for glucose
      systolic INTEGER,                -- for bp
      diastolic INTEGER,               -- for bp
      note TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// ===== HELPERS =====
function nowIso() {
  return new Date().toISOString();
}

function signToken(user) {
  return jwt.sign({ uid: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d"
  });
}

function authMiddleware(req, res, next) {
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

function normalizePhone(phone) {
  // Expect E.164 format like +15625416709
  // If user typed 5625416709, we assume US and convert.
  const p = String(phone || "").trim();
  if (p.startsWith("+")) return p;
  const digits = p.replace(/\D/g, "");
  if (digits.length === 10) return "+1" + digits;
  return p; // best effort
}

// ===== ROUTES =====
app.get("/health", (req, res) => {
  res.json({ ok: true, hasTwilioVerify });
});

// Register (only creates user + sends OTP)
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const phoneNorm = normalizePhone(phone);

    const pass_hash = await bcrypt.hash(String(password), 10);

    db.run(
      `INSERT INTO users (name, email, phone, pass_hash, verified, created_at)
       VALUES (?, ?, ?, ?, 0, ?)`,
      [String(name).trim(), emailNorm, phoneNorm, pass_hash, nowIso()],
      async function (err) {
        if (err) {
          if (String(err).includes("UNIQUE")) {
            return res.status(409).json({ error: "Email already registered" });
          }
          return res.status(500).json({ error: "DB error", details: String(err) });
        }

        // Send SMS OTP using Twilio Verify
        if (!hasTwilioVerify) {
          return res.status(200).json({
            ok: true,
            message:
              "Registered, but Twilio Verify is not configured. Add TWILIO_* env vars."
          });
        }

        try {
          await twilioClient.verify.v2
            .services(TWILIO_VERIFY_SERVICE_SID)
            .verifications.create({ to: phoneNorm, channel: "sms" });

          return res.status(200).json({
            ok: true,
            message: "User registered. SMS verification code sent.",
            phone: phoneNorm
          });
        } catch (e) {
          return res.status(200).json({
            ok: true,
            message:
              "User registered, but SMS failed to send. Check Twilio Verify Service + verified phone in trial.",
            details: String(e.message || e)
          });
        }
      }
    );
  } catch (e) {
    res.status(500).json({ error: "Server error", details: String(e.message || e) });
  }
});

// Verify OTP (marks user verified)
app.post("/api/verify", async (req, res) => {
  try {
    const { email, phone, code } = req.body || {};
    if (!email || !phone || !code) {
      return res.status(400).json({ error: "Missing fields" });
    }
    if (!hasTwilioVerify) {
      return res.status(400).json({ error: "Twilio Verify not configured" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const phoneNorm = normalizePhone(phone);

    // Ensure user exists
    db.get(
      `SELECT id, email, phone, verified FROM users WHERE email = ?`,
      [emailNorm],
      async (err, user) => {
        if (err) return res.status(500).json({ error: "DB error" });
        if (!user) return res.status(404).json({ error: "User not found" });

        if (normalizePhone(user.phone) !== phoneNorm) {
          return res.status(400).json({ error: "Phone does not match this email" });
        }

        try {
          const check = await twilioClient.verify.v2
            .services(TWILIO_VERIFY_SERVICE_SID)
            .verificationChecks.create({ to: phoneNorm, code: String(code).trim() });

          if (check.status !== "approved") {
            return res.status(400).json({ error: "Invalid code", status: check.status });
          }

          db.run(
            `UPDATE users SET verified = 1 WHERE id = ?`,
            [user.id],
            (err2) => {
              if (err2) return res.status(500).json({ error: "DB update failed" });

              return res.json({ ok: true, message: "Verified successfully" });
            }
          );
        } catch (e) {
          return res.status(400).json({ error: "Verify failed", details: String(e.message || e) });
        }
      }
    );
  } catch (e) {
    res.status(500).json({ error: "Server error", details: String(e.message || e) });
  }
});

// Login (only if verified) -> returns JWT
app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });

  const emailNorm = String(email).trim().toLowerCase();

  db.get(
    `SELECT id, email, pass_hash, verified FROM users WHERE email = ?`,
    [emailNorm],
    async (err, user) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!user) return res.status(404).json({ error: "User not found" });
      if (!user.verified) return res.status(403).json({ error: "Email/phone not verified" });

      const ok = await bcrypt.compare(String(password), user.pass_hash);
      if (!ok) return res.status(401).json({ error: "Invalid email or password" });

      const token = signToken(user);
      return res.json({ ok: true, token });
    }
  );
});

// Add reading (glucose or bp) + auto date/time
app.post("/api/readings", authMiddleware, (req, res) => {
  const uid = req.user.uid;
  const { type, glucose_mgdl, systolic, diastolic, note } = req.body || {};

  if (type !== "glucose" && type !== "bp") {
    return res.status(400).json({ error: "type must be 'glucose' or 'bp'" });
  }

  const created_at = nowIso();

  if (type === "glucose") {
    const g = Number(glucose_mgdl);
    if (!Number.isFinite(g) || g <= 0) return res.status(400).json({ error: "Invalid glucose" });

    db.run(
      `INSERT INTO readings (user_id, type, glucose_mgdl, systolic, diastolic, note, created_at)
       VALUES (?, 'glucose', ?, NULL, NULL, ?, ?)`,
      [uid, Math.round(g), note ? String(note) : null, created_at],
      function (err) {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json({ ok: true, id: this.lastID, created_at });
      }
    );
  } else {
    const s = Number(systolic);
    const d = Number(diastolic);
    if (!Number.isFinite(s) || !Number.isFinite(d) || s <= 0 || d <= 0) {
      return res.status(400).json({ error: "Invalid blood pressure" });
    }

    db.run(
      `INSERT INTO readings (user_id, type, glucose_mgdl, systolic, diastolic, note, created_at)
       VALUES (?, 'bp', NULL, ?, ?, ?, ?)`,
      [uid, Math.round(s), Math.round(d), note ? String(note) : null, created_at],
      function (err) {
        if (err) return res.status(500).json({ error: "DB error" });
        res.json({ ok: true, id: this.lastID, created_at });
      }
    );
  }
});

// List readings
app.get("/api/readings", authMiddleware, (req, res) => {
  const uid = req.user.uid;

  db.all(
    `SELECT id, type, glucose_mgdl, systolic, diastolic, note, created_at
     FROM readings
     WHERE user_id = ?
     ORDER BY datetime(created_at) DESC
     LIMIT 200`,
    [uid],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json({ ok: true, rows });
    }
  );
});

// Serve index by default
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
  console.log("Twilio Verify configured:", hasTwilioVerify);
});