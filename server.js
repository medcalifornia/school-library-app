const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sgMail = require("@sendgrid/mail");

const app = express();
app.use(express.json());

// Serve frontend
app.use(express.static("public"));

const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// Only set SendGrid if key exists (IMPORTANT)
if (SENDGRID_API_KEY) sgMail.setApiKey(SENDGRID_API_KEY);

// In-memory store (prototype)
const users = new Map(); // key=email, value={name,email,passwordHash,verified,code}
const readings = new Map(); // key=email, value=[{value,note,ts}]

// Health
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "API is healthy" });
});

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: "Missing name/email/password" });
    }

    const key = email.toLowerCase().trim();
    if (users.has(key)) {
      return res.status(400).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const code = String(Math.floor(100000 + Math.random() * 900000));

    users.set(key, { name, email: key, passwordHash, verified: false, code });

    // Email code (if SendGrid configured)
    if (SENDGRID_API_KEY && FROM_EMAIL) {
      await sgMail.send({
        to: key,
        from: FROM_EMAIL,
        subject: "Your verification code",
        text: `Your verification code is: ${code}`,
      });
    } else {
      // If SendGrid is not configured, still succeed (TEST MODE)
      // You can see the code in the response for testing on Azure.
      return res.json({
        message: "Registered (TEST MODE). Configure SendGrid to email codes.",
        testCode: code
      });
    }

    return res.json({ message: "User registered. Check email for code." });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(500).json({ error: "Register failed", details: String(err.message || err) });
  }
});

// Verify
app.post("/api/verify", (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: "Missing email/code" });

  const key = email.toLowerCase().trim();
  const user = users.get(key);
  if (!user) return res.status(404).json({ error: "User not found" });

  if (String(user.code) !== String(code)) {
    return res.status(400).json({ error: "Invalid code" });
  }

  user.verified = true;
  user.code = null;
  users.set(key, user);

  res.json({ message: "Email verified. You can login now." });
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing email/password" });

  const key = email.toLowerCase().trim();
  const user = users.get(key);
  if (!user) return res.status(400).json({ error: "Invalid email or password" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: "Invalid email or password" });

  if (!user.verified) return res.status(403).json({ error: "Email not verified" });

  const token = jwt.sign({ email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ message: "Logged in", token, name: user.name });
});

// Auth middleware
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Add reading
app.post("/api/readings", requireAuth, (req, res) => {
  const { value, note } = req.body || {};
  const num = Number(value);
  if (!Number.isFinite(num)) return res.status(400).json({ error: "Glucose value must be a number" });

  const email = req.user.email;
  const arr = readings.get(email) || [];
  arr.push({ value: num, note: note || "", ts: new Date().toISOString() });
  readings.set(email, arr);

  res.json({ message: "Reading added", count: arr.length });
});

// Get readings
app.get("/api/readings", requireAuth, (req, res) => {
  const email = req.user.email;
  res.json(readings.get(email) || []);
});

// Root page
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
