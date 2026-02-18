"use strict";

const sql = require("mssql");
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const twilio = require("twilio");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 8080;

// ================= DATABASE CONFIG (Azure SQL) =================
// Put these in Azure App Service -> Configuration -> Application settings
// DB_SERVER = project2026.database.windows.net
// DB_NAME   = Diabetictracker
// DB_USER   = medcalifornia
// DB_PASSWORD = ********
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000,
  },
};

// Create one global pool (recommended)
let poolPromise = null;
function getPool() {
  if (!poolPromise) {
    poolPromise = sql.connect(dbConfig);
  }
  return poolPromise;
}

// ================= TWILIO (Verify) =================
const hasTwilio =
  process.env.TWILIO_ACCOUNT_SID &&
  process.env.TWILIO_AUTH_TOKEN &&
  process.env.TWILIO_VERIFY_SERVICE_SID;

const twilioClient = hasTwilio
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;

// ================= HELPERS =================
function normalizePhone(phone) {
  if (!phone) return "";
  let p = String(phone).trim();
  if (!p.startsWith("+")) p = "+" + p;
  return p;
}

// In-memory reset tokens (simple + safe enough for now)
const resetTokens = new Map(); // token -> { phone, expiresAt }
function createResetToken(phone) {
  const token = crypto.randomBytes(24).toString("hex");
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  resetTokens.set(token, { phone, expiresAt });
  return token;
}
function verifyResetToken(token, phone) {
  const item = resetTokens.get(token);
  if (!item) return false;
  if (Date.now() > item.expiresAt) {
    resetTokens.delete(token);
    return false;
  }
  if (item.phone !== phone) return false;
  return true;
}
function consumeResetToken(token) {
  resetTokens.delete(token);
}

// ================= INIT TABLES (auto-create if missing) =================
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
        Type NVARCHAR(20) NOT NULL,       -- 'glucose' or 'bp'
        Value NVARCHAR(40) NOT NULL,      -- e.g. '110' or '120/80'
        Note NVARCHAR(120) NULL,
        Ts DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        CONSTRAINT FK_Readings_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id)
      );
      CREATE INDEX IX_Readings_UserId_Ts ON dbo.Readings(UserId, Ts);
    END
  `);
}

// ================= BASIC ROUTES =================
app.get("/health", (req, res) => {
  res.json({ status: "OK", message: "Server Running" });
});

// ================= DB TEST ROUTE =================
app.get("/api/db-test", async (req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query("SELECT GETDATE() AS currentTime");
    res.json({
      connected: true,
      status: "Database Connected Successfully",
      time: result.recordset[0].currentTime,
    });
  } catch (err) {
    res.status(500).json({
      connected: false,
      error: "Database Connection Failed",
      details: err.message,
    });
  }
});

// ================= AUTH =================
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const e = String(email).trim().toLowerCase();
    const p = normalizePhone(phone);
    const hash = await bcrypt.hash(String(password), 10);

    const pool = await getPool();

    // Check duplicates
    const dup = await pool
      .request()
      .input("Email", sql.NVarChar(255), e)
      .input("Phone", sql.NVarChar(32), p)
      .query(`SELECT TOP 1 Id FROM dbo.Users WHERE Email=@Email OR Phone=@Phone`);

    if (dup.recordset.length) {
      return res.status(400).json({ error: "Email or phone already used" });
    }

    await pool
      .request()
      .input("Name", sql.NVarChar(120), String(name).trim())
      .input("Email", sql.NVarChar(255), e)
      .input("Phone", sql.NVarChar(32), p)
      .input("PasswordHash", sql.NVarChar(255), hash)
      .query(
        `INSERT INTO dbo.Users (Name, Email, Phone, PasswordHash)
         VALUES (@Name, @Email, @Phone, @PasswordHash)`
      );

    res.json({ message: "Registered successfully" });
  } catch (err) {
    res.status(500).json({ error: "Register failed", details: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const e = String(email || "").trim().toLowerCase();
    if (!e || !password) return res.status(400).json({ error: "Missing fields" });

    const pool = await getPool();

    const result = await pool
      .request()
      .input("Email", sql.NVarChar(255), e)
      .query(
        `SELECT TOP 1 Id, Name, Phone, PasswordHash
         FROM dbo.Users
         WHERE Email=@Email`
      );

    if (!result.recordset.length) return res.status(400).json({ error: "Invalid email or password" });

    const user = result.recordset[0];
    const ok = await bcrypt.compare(String(password), String(user.PasswordHash));
    if (!ok) return res.status(400).json({ error: "Invalid email or password" });

    // Return userId + name (+ phone so you can store it for masked phone UI)
    res.json({
      message: "Login OK",
      userId: user.Id,
      name: user.Name,
      phone: user.Phone,
    });
  } catch (err) {
    res.status(500).json({ error: "Login failed", details: err.message });
  }
});

// ================= READINGS =================
app.post("/api/readings", async (req, res) => {
  try {
    const { userId, type, value, note } = req.body || {};
    if (!userId || !type || !value) return res.status(400).json({ error: "Missing fields" });

    const pool = await getPool();
    await pool
      .request()
      .input("UserId", sql.UniqueIdentifier, userId)
      .input("Type", sql.NVarChar(20), String(type))
      .input("Value", sql.NVarChar(40), String(value))
      .input("Note", sql.NVarChar(120), note ? String(note) : "")
      .query(
        `INSERT INTO dbo.Readings (UserId, Type, Value, Note)
         VALUES (@UserId, @Type, @Value, @Note)`
      );

    res.json({ message: "Saved" });
  } catch (err) {
    res.status(500).json({ error: "Save failed", details: err.message });
  }
});

app.get("/api/readings/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const pool = await getPool();

    const result = await pool
      .request()
      .input("UserId", sql.UniqueIdentifier, userId)
      .query(
        `SELECT Id, UserId, Type, Value, Note, Ts
         FROM dbo.Readings
         WHERE UserId=@UserId
         ORDER BY Ts ASC`
      );

    res.json(
      result.recordset.map((r) => ({
        id: r.Id,
        userId: r.UserId,
        type: r.Type,
        value: r.Value,
        note: r.Note || "",
        ts: r.Ts,
      }))
    );
  } catch (err) {
    res.status(500).json({ error: "Load failed", details: err.message });
  }
});

app.get("/api/chart/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const pool = await getPool();

    const result = await pool
      .request()
      .input("UserId", sql.UniqueIdentifier, userId)
      .query(
        `SELECT Type, Value, Note, Ts
         FROM dbo.Readings
         WHERE UserId=@UserId
         ORDER BY Ts ASC`
      );

    const readings = result.recordset;

    // group by YYYY-MM-DD
    const byDate = {};
    for (const r of readings) {
      const d = new Date(r.Ts).toISOString().slice(0, 10);
      byDate[d] = byDate[d] || { glucose: [], bpSys: [], bpDia: [] };

      if (r.Type === "glucose") {
        const n = Number(r.Value);
        if (!Number.isNaN(n)) byDate[d].glucose.push(n);
      } else if (r.Type === "bp") {
        const [s, di] = String(r.Value).split("/").map((x) => Number(x));
        if (!Number.isNaN(s)) byDate[d].bpSys.push(s);
        if (!Number.isNaN(di)) byDate[d].bpDia.push(di);
      }
    }

    const labels = Object.keys(byDate).sort();
    const avg = (arr) => (arr.length ? Math.round(arr.reduce((a, b) => a + b, 0) / arr.length) : null);

    res.json({
      labels,
      glucoseAvg: labels.map((d) => avg(byDate[d].glucose)),
      sysAvg: labels.map((d) => avg(byDate[d].bpSys)),
      diaAvg: labels.map((d) => avg(byDate[d].bpDia)),
    });
  } catch (err) {
    res.status(500).json({ error: "Chart failed", details: err.message });
  }
});

// ================= FORGOT PASSWORD (SMS via Twilio Verify) =================
app.post("/api/forgot-password", async (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    if (!phone) return res.status(400).json({ error: "Phone required" });
    if (!hasTwilio) return res.status(500).json({ error: "Twilio not configured on server" });

    // check phone exists
    const pool = await getPool();
    const userCheck = await pool
      .request()
      .input("Phone", sql.NVarChar(32), phone)
      .query(`SELECT TOP 1 Id FROM dbo.Users WHERE Phone=@Phone`);

    if (!userCheck.recordset.length) return res.status(400).json({ error: "Phone not found" });

    await twilioClient.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications.create({ to: phone, channel: "sms" });

    res.json({ message: "Code sent" });
  } catch (err) {
    res.status(500).json({ error: "Send code failed", details: err.message });
  }
});

app.post("/api/verify-reset-code", async (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    const code = String(req.body?.code || "").trim();
    if (!phone || !code) return res.status(400).json({ error: "Phone & code required" });
    if (!hasTwilio) return res.status(500).json({ error: "Twilio not configured on server" });

    const check = await twilioClient.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks.create({ to: phone, code });

    if (check.status !== "approved") return res.status(400).json({ error: "Invalid code" });

    // Issue short-lived reset token (safer than letting reset without proof)
    const resetToken = createResetToken(phone);

    res.json({ message: "Verified", resetToken });
  } catch (err) {
    res.status(500).json({ error: "Verify failed", details: err.message });
  }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    const newPassword = String(req.body?.newPassword || "");
    const resetToken = String(req.body?.resetToken || "");
    if (!phone || !newPassword) return res.status(400).json({ error: "Bad input" });
    if (newPassword.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

    // Require resetToken (professional & secure)
    if (!resetToken || !verifyResetToken(resetToken, phone)) {
      return res.status(400).json({ error: "Reset token missing/expired. Please verify code again." });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    const pool = await getPool();

    const upd = await pool
      .request()
      .input("Phone", sql.NVarChar(32), phone)
      .input("PasswordHash", sql.NVarChar(255), hash)
      .query(`UPDATE dbo.Users SET PasswordHash=@PasswordHash WHERE Phone=@Phone`);

    consumeResetToken(resetToken);

    if (!upd.rowsAffected?.[0]) return res.status(400).json({ error: "Phone not found" });

    res.json({ message: "Password updated" });
  } catch (err) {
    res.status(500).json({ error: "Reset failed", details: err.message });
  }
});

// ================= DEFAULT ROUTE =================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ================= START SERVER =================
(async () => {
  try {
    await ensureTables();
    app.listen(PORT, () => console.log("Server running on port", PORT));
  } catch (err) {
    console.error("Startup failed:", err);
    process.exit(1);
  }
})();