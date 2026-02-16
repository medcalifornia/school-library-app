const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sgMail = require("@sendgrid/mail");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ====== ENV ======
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL;
const JWT_SECRET = process.env.JWT_SECRET;

if (SENDGRID_API_KEY) sgMail.setApiKey(SENDGRID_API_KEY);

// ====== In-memory "DB" (for demo) ======
// Later we replace this with a real DB.
let users = []; // { id, email, passwordHash, verified, verifyCodeHash, verifyExpiresAt }
let nextUserId = 1;

// ====== Helpers ======
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generate6DigitCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function sendVerificationEmail(toEmail, code) {
  if (!SENDGRID_API_KEY || !FROM_EMAIL) {
    // If you forgot to configure email service, fail clearly
    throw new Error("Email is not configured. Set SENDGRID_API_KEY and FROM_EMAIL in Azure.");
  }

  const msg = {
    to: toEmail,
    from: FROM_EMAIL,
    subject: "Your verification code",
    text: `Your verification code is: ${code}\n\nThis code expires in 10 minutes.`,
  };

  await sgMail.send(msg);
}

function signToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const [type, token] = header.split(" ");
    if (type !== "Bearer" || !token) {
      return res.status(401).json({ error: "Missing token" });
    }
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ====== Health ======
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", service: "diabetes-tracker-auth" });
});

// ====== AUTH ======

// Register: email + password → send code
app.post("/api/auth/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!isValidEmail(email)) return res.status(400).json({ error: "Invalid email" });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    if (!JWT_SECRET) return res.status(500).json({ error: "Server missing JWT_SECRET" });

    const existing = users.find(u => u.email === email);
    if (existing) {
      // Security: don’t reveal much; but for student project we can be direct
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const code = generate6DigitCode();
    const verifyCodeHash = await bcrypt.hash(code, 10);
    const verifyExpiresAt = Date.now() + 10 * 60 * 1000; // 10 min

    const user = {
      id: nextUserId++,
      email,
      passwordHash,
      verified: false,
      verifyCodeHash,
      verifyExpiresAt
    };
    users.push(user);

    await sendVerificationEmail(email, code);

    res.status(201).json({
      status: "OK",
      message: "Registered. Check your email for the verification code."
    });
  } catch (err) {
    res.status(500).json({ error: err.message || "Registration failed" });
  }
});

// Verify code
app.post("/api/auth/verify", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || "").trim();

    const user = users.find(u => u.email === email);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.verified) return res.json({ status: "OK", message: "Already verified" });

    if (!user.verifyExpiresAt || Date.now() > user.verifyExpiresAt) {
      return res.status(400).json({ error: "Code expired. Please register again (demo) or implement resend." });
    }

    const ok = await bcrypt.compare(code, user.verifyCodeHash);
    if (!ok) return res.status(400).json({ error: "Invalid code" });

    user.verified = true;
    user.verifyCodeHash = null;
    user.verifyExpiresAt = null;

    res.json({ status: "OK", message: "Email verified. You can now login." });
  } catch {
    res.status(500).json({ error: "Verification failed" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error: "Invalid email or password" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password" });

    if (!user.verified) return res.status(403).json({ error: "Email not verified" });

    const token = signToken(user);
    res.json({ status: "OK", token });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

// Who am I (protected)
app.get("/api/auth/me", authRequired, (req, res) => {
  res.json({ status: "OK", user: req.user });
});

// ====== Your diabetes APIs can be protected now ======
// Example protected endpoint:
app.get("/api/secure/example", authRequired, (req, res) => {
  res.json({ status: "OK", message: "You are authenticated", user: req.user });
});

// Serve UI
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
