// server.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sgMail = require("@sendgrid/mail");
const path = require("path");

const app = express();
app.use(express.json());

// ===== ENV =====
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("Missing JWT_SECRET in App Service Application settings");
}
if (SENDGRID_API_KEY) sgMail.setApiKey(SENDGRID_API_KEY);

// ===== In-memory DB (temporary) =====
// IMPORTANT: This resets if Azure restarts your app.
// Later we can move to Cosmos DB / Azure SQL.
const usersByEmail = new Map(); // email -> user
// user shape:
// { id, name, email, passwordHash, verified, verifyCode, verifyExpiresAt, readings: [] }

const makeId = () => Math.random().toString(36).slice(2) + Date.now().toString(36);
const make6DigitCode = () => String(Math.floor(100000 + Math.random() * 900000));

function isValidEmail(email) {
  return typeof email === "string" && email.includes("@") && email.includes(".");
}

function signToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // {sub,email,name}
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ===== API ROUTES (IMPORTANT: put BEFORE static hosting) =====

app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "API is healthy" });
});

// Register: name, email, password
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (!name || typeof name !== "string") {
      return res.status(400).json({ error: "Name is required" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Valid email is required" });
    }
    if (!password || typeof password !== "string" || password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (usersByEmail.has(normalizedEmail)) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const verifyCode = make6DigitCode();
    const verifyExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    const user = {
      id: makeId(),
      name: name.trim(),
      email: normalizedEmail,
      passwordHash,
      verified: false,
      verifyCode,
      verifyExpiresAt,
      readings: [],
      createdAt: new Date().toISOString(),
    };

    usersByEmail.set(normalizedEmail, user);

    // Send email (if configured)
    if (SENDGRID_API_KEY && FROM_EMAIL) {
      const msg = {
        to: normalizedEmail,
        from: FROM_EMAIL,
        subject: "Your Diabetes Tracker verification code",
        text: `Your verification code is: ${verifyCode}\n\nThis code expires in 10 minutes.`,
      };

      try {
        await sgMail.send(msg);
      } catch (e) {
        console.error("SendGrid error:", e?.response?.body || e.message || e);
        // Still allow registration, but tell user email failed
        return res.status(201).json({
          ok: true,
          message:
            "User registered, but email failed to send. Check SENDGRID_API_KEY / FROM_EMAIL in Azure settings.",
        });
      }

      return res.status(201).json({
        ok: true,
        message: "User registered. Check email for code.",
      });
    }

    // If SendGrid not set, return code for testing
    return res.status(201).json({
      ok: true,
      message:
        "User registered. Email service not configured. For testing, use the code returned.",
      code: verifyCode,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error in register" });
  }
});

// Verify: email + code
app.post("/api/verify", (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ error: "Valid email is required" });
    if (!code || typeof code !== "string") return res.status(400).json({ error: "Code is required" });

    const normalizedEmail = email.trim().toLowerCase();
    const user = usersByEmail.get(normalizedEmail);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.verified) {
      return res.json({ ok: true, message: "Already verified. You can log in." });
    }

    if (Date.now() > user.verifyExpiresAt) {
      return res.status(400).json({ error: "Code expired. Register again (or we can add resend)." });
    }

    if (String(code).trim() !== String(user.verifyCode)) {
      return res.status(400).json({ error: "Invalid code" });
    }

    user.verified = true;
    user.verifyCode = null;
    user.verifyExpiresAt = null;

    return res.json({ ok: true, message: "Email verified. You can now log in." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error in verify" });
  }
});

// Login: email + password => JWT
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ error: "Valid email is required" });
    if (!password) return res.status(400).json({ error: "Password is required" });

    const normalizedEmail = email.trim().toLowerCase();
    const user = usersByEmail.get(normalizedEmail);
    if (!user) return res.status(404).json({ error: "User not found" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password" });

    if (!user.verified) return res.status(403).json({ error: "Email not verified" });

    const token = signToken(user);

    return res.json({
      ok: true,
      message: "Logged in",
      token,
      user: { name: user.name, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error in login" });
  }
});

// Add glucose reading (auth required)
app.post("/api/readings", auth, (req, res) => {
  try {
    const { glucose, note } = req.body || {};
    const value = Number(glucose);

    if (!Number.isFinite(value) || value <= 0) {
      return res.status(400).json({ error: "glucose must be a positive number" });
    }

    const user = usersByEmail.get(req.user.email);
    if (!user) return res.status(404).json({ error: "User not found" });

    const reading = {
      id: makeId(),
      glucose: value,
      note: typeof note === "string" ? note.trim() : "",
      at: new Date().toISOString(),
    };

    user.readings.unshift(reading);
    return res.status(201).json({ ok: true, message: "Reading added", reading });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error adding reading" });
  }
});

// Get my readings (auth required)
app.get("/api/readings", auth, (req, res) => {
  try {
    const user = usersByEmail.get(req.user.email);
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json({ ok: true, readings: user.readings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error loading readings" });
  }
});

// ===== STATIC FRONTEND (MUST BE AFTER API ROUTES) =====
app.use(express.static(path.join(__dirname, "public")));

// Optional: force root to index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ===== START =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
