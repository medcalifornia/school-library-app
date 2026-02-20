"use strict";

const sql = require("mssql");
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const twilio = require("twilio");
const crypto = require("crypto");
const cors = require("cors");

const app = express();

// ===== Middleware =====
app.disable("x-powered-by");
app.use(cors());
app.use(express.json({ limit: "256kb" }));

const PORT = process.env.PORT || 8080;

// ===== DB Config =====
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: { encrypt: true, trustServerCertificate: false },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
};

let poolPromise = null;
function getPool() {
  if (!poolPromise) poolPromise = sql.connect(dbConfig);
  return poolPromise;
}

// ===== Twilio Setup =====
const hasTwilio = !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_VERIFY_SERVICE_SID);
const twilioClient = hasTwilio
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;

function normalizePhone(phone) {
  if (!phone) return "";
  let p = String(phone).trim().replace(/\s+/g, '');
  return p.startsWith("+") ? p : "+" + p;
}

// ===== Password Reset Tokens (in-memory) =====
const resetTokens = new Map();
function createResetToken(phone) {
  const token = crypto.randomBytes(24).toString("hex");
  resetTokens.set(token, { phone, expiresAt: Date.now() + 10 * 60 * 1000 });
  return token;
}
function verifyResetToken(token, phone) {
  const item = resetTokens.get(token);
  if (!item || Date.now() > item.expiresAt || item.phone !== phone) {
    resetTokens.delete(token);
    return false;
  }
  return true;
}
function consumeResetToken(token) {
  resetTokens.delete(token);
}

// ===== Helpers =====
function safeStr(x, max = 255) {
  if (x == null) return "";
  const s = String(x).trim();
  return s.length > max ? s.slice(0, max) : s;
}

function isValidGuid(id) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(id || ""));
}

// ===== Ensure Tables =====
async function ensureTables() {
  const pool = await getPool();

  await pool.request().query(`
    IF OBJECT_ID('dbo.Users', 'U') IS NULL
    BEGIN
      CREATE TABLE dbo.Users (
        Id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWID() PRIMARY KEY,
        Name NVARCHAR(120) NOT NULL,
        Email NVARCHAR(255) NOT NULL UNIQUE,
        Phone NVARCHAR(32) NOT NULL UNIQUE,
        PasswordHash NVARCHAR(255) NOT NULL,
        CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
      );
    END
  `);

  await pool.request().query(`
    IF OBJECT_ID('dbo.Readings', 'U') IS NULL
    BEGIN
      CREATE TABLE dbo.Readings (
        Id UNIQUEIDENTIFIER NOT NULL DEFAULT NEWID() PRIMARY KEY,
        UserId UNIQUEIDENTIFIER NOT NULL,
        Type NVARCHAR(20) NOT NULL,
        Value NVARCHAR(40) NOT NULL,
        Note NVARCHAR(120) NULL,
        Ts DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        CONSTRAINT FK_Readings_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id)
      );
      CREATE INDEX IX_Readings_UserId_Ts ON dbo.Readings(UserId, Ts DESC);
    END
  `);
}

// ===== Cache Control (لمنع التخزين المؤقت) =====
app.use((req, res, next) => {
  if (req.method === "GET" && (req.path.endsWith(".html") || req.path.endsWith(".css") || req.path.endsWith(".js"))) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  next();
});

// ===== Static Files =====
app.use(express.static(path.join(__dirname, "public"), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith(".html") || filePath.endsWith(".css") || filePath.endsWith(".js")) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    }
  },
}));

// ==================== API Routes ====================

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "OK", message: "Server Running" });
});

// ===== Auth =====
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const normalizedEmail = safeStr(email, 255).toLowerCase();
    const normalizedPhone = normalizePhone(phone);
    const normalizedName = safeStr(name, 120);

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const hash = await bcrypt.hash(password, 10);
    const pool = await getPool();

    const duplicateCheck = await pool
      .request()
      .input("Email", sql.NVarChar(255), normalizedEmail)
      .input("Phone", sql.NVarChar(32), normalizedPhone)
      .query("SELECT TOP 1 Id FROM dbo.Users WHERE Email = @Email OR Phone = @Phone");

    if (duplicateCheck.recordset.length) {
      return res.status(400).json({ error: "Email or phone already in use" });
    }

    await pool
      .request()
      .input("Name", sql.NVarChar(120), normalizedName)
      .input("Email", sql.NVarChar(255), normalizedEmail)
      .input("Phone", sql.NVarChar(32), normalizedPhone)
      .input("PasswordHash", sql.NVarChar(255), hash)
      .query("INSERT INTO dbo.Users (Name, Email, Phone, PasswordHash) VALUES (@Name, @Email, @Phone, @PasswordHash)");

    res.json({ message: "Registered successfully" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const normalizedEmail = safeStr(email, 255).toLowerCase();

    if (!normalizedEmail || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const pool = await getPool();
    const result = await pool
      .request()
      .input("Email", sql.NVarChar(255), normalizedEmail)
      .query("SELECT TOP 1 Id, Name, Phone, PasswordHash FROM dbo.Users WHERE Email = @Email");

    if (!result.recordset.length) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const user = result.recordset[0];
    const isValid = await bcrypt.compare(password, user.PasswordHash);

    if (!isValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    res.json({
      message: "Login successful",
      userId: user.Id,
      name: user.Name,
      phone: user.Phone
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ===== Readings =====
app.post("/api/readings", async (req, res) => {
  try {
    const { userId, type, value, note } = req.body || {};
    
    if (!userId || !type || !value) {
      return res.status(400).json({ error: "Missing fields" });
    }
    if (!isValidGuid(userId)) {
      return res.status(400).json({ error: "Invalid userId" });
    }

    const normalizedType = String(type).toLowerCase();
    if (!["glucose", "bp"].includes(normalizedType)) {
      return res.status(400).json({ error: "Invalid type" });
    }

    const safeValue = safeStr(value, 40);
    const safeNote = note ? safeStr(note, 120) : null;

    // Validate based on type
    if (normalizedType === "glucose") {
      const num = Number(safeValue);
      if (isNaN(num) || num <= 0) {
        return res.status(400).json({ error: "Invalid glucose value" });
      }
    } else if (normalizedType === "bp") {
      const parts = safeValue.split("/");
      if (parts.length !== 2) {
        return res.status(400).json({ error: "Invalid BP format (use systolic/diastolic)" });
      }
      const [s, d] = parts.map(Number);
      if (isNaN(s) || isNaN(d) || s <= 0 || d <= 0) {
        return res.status(400).json({ error: "Invalid BP numbers" });
      }
    }

    const pool = await getPool();
    await pool
      .request()
      .input("UserId", sql.UniqueIdentifier, userId)
      .input("Type", sql.NVarChar(20), normalizedType)
      .input("Value", sql.NVarChar(40), safeValue)
      .input("Note", sql.NVarChar(120), safeNote)
      .query("INSERT INTO dbo.Readings (UserId, Type, Value, Note) VALUES (@UserId, @Type, @Value, @Note)");

    res.json({ message: "Reading saved successfully" });
  } catch (err) {
    console.error("Save reading error:", err);
    res.status(500).json({ error: "Failed to save reading" });
  }
});

app.get("/api/readings/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    if (!isValidGuid(userId)) {
      return res.status(400).json({ error: "Invalid userId" });
    }

    const pool = await getPool();
    const result = await pool
      .request()
      .input("UserId", sql.UniqueIdentifier, userId)
      .query("SELECT Id, Type, Value, Note, Ts FROM dbo.Readings WHERE UserId = @UserId ORDER BY Ts DESC");

    const readings = result.recordset.map(r => ({
      id: r.Id,
      type: r.Type,
      value: r.Value,
      note: r.Note || "",
      ts: r.Ts
    }));

    res.json(readings);
  } catch (err) {
    console.error("Load readings error:", err);
    res.status(500).json({ error: "Failed to load readings" });
  }
});

app.put("/api/readings/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { userId, value, note } = req.body || {};

    if (!id || !userId || !value) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (!isValidGuid(id) || !isValidGuid(userId)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const safeValue = safeStr(value, 40);
    const safeNote = note ? safeStr(note, 120) : null;

    const pool = await getPool();
    const result = await pool
      .request()
      .input("Id", sql.UniqueIdentifier, id)
      .input("UserId", sql.UniqueIdentifier, userId)
      .input("Value", sql.NVarChar(40), safeValue)
      .input("Note", sql.NVarChar(120), safeNote)
      .query("UPDATE dbo.Readings SET Value = @Value, Note = @Note WHERE Id = @Id AND UserId = @UserId");

    if (!result.rowsAffected?.[0]) {
      return res.status(404).json({ error: "Reading not found" });
    }

    res.json({ message: "Reading updated successfully" });
  } catch (err) {
    console.error("Update reading error:", err);
    res.status(500).json({ error: "Failed to update reading" });
  }
});

app.delete("/api/readings/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.body || {};

    if (!id || !userId) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (!isValidGuid(id) || !isValidGuid(userId)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    const pool = await getPool();
    const result = await pool
      .request()
      .input("Id", sql.UniqueIdentifier, id)
      .input("UserId", sql.UniqueIdentifier, userId)
      .query("DELETE FROM dbo.Readings WHERE Id = @Id AND UserId = @UserId");

    if (!result.rowsAffected?.[0]) {
      return res.status(404).json({ error: "Reading not found" });
    }

    res.json({ message: "Reading deleted successfully" });
  } catch (err) {
    console.error("Delete reading error:", err);
    res.status(500).json({ error: "Failed to delete reading" });
  }
});

// ===== Forgot Password (Twilio) =====
app.post("/api/forgot-password", async (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    if (!phone) return res.status(400).json({ error: "Phone number required" });
    if (!hasTwilio) return res.status(500).json({ error: "SMS service not configured" });

    const pool = await getPool();
    const userCheck = await pool
      .request()
      .input("Phone", sql.NVarChar(32), phone)
      .query("SELECT TOP 1 Id FROM dbo.Users WHERE Phone = @Phone");

    if (!userCheck.recordset.length) {
      return res.status(404).json({ error: "Phone number not registered" });
    }

    await twilioClient.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({ to: phone, channel: "sms" });

    res.json({ message: "Verification code sent" });
  } catch (err) {
    console.error("Send code error:", err);
    res.status(500).json({ error: "Failed to send verification code" });
  }
});

app.post("/api/verify-reset-code", async (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    const code = String(req.body?.code || "").trim();

    if (!phone || !code) return res.status(400).json({ error: "Phone and code required" });
    if (!hasTwilio) return res.status(500).json({ error: "SMS service not configured" });

    const verification = await twilioClient.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({ to: phone, code });

    if (verification.status !== "approved") {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    const resetToken = createResetToken(phone);
    res.json({ message: "Code verified", resetToken });
  } catch (err) {
    console.error("Verify code error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    const newPassword = String(req.body?.newPassword || "");
    const resetToken = String(req.body?.resetToken || "");

    if (!phone || !newPassword) return res.status(400).json({ error: "Missing required fields" });
    if (newPassword.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

    if (!resetToken || !verifyResetToken(resetToken, phone)) {
      return res.status(400).json({ error: "Invalid or expired reset token" });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    const pool = await getPool();

    const result = await pool
      .request()
      .input("Phone", sql.NVarChar(32), phone)
      .input("PasswordHash", sql.NVarChar(255), hash)
      .query("UPDATE dbo.Users SET PasswordHash = @PasswordHash WHERE Phone = @Phone");

    consumeResetToken(resetToken);

    if (!result.rowsAffected?.[0]) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// ===== Root =====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ===== Start Server =====
(async () => {
  try {
    await ensureTables();
    app.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error("❌ Startup failed:", err);
    process.exit(1);
  }
})();