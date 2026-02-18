const sql = require("mssql");
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const twilio = require("twilio");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 8080;

// ================= DATABASE CONFIG =================
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

// ================= DB TEST ROUTE =================
app.get("/api/db-test", async (req, res) => {
  try {
    await sql.connect(dbConfig);
    const result = await sql.query("SELECT GETDATE() AS currentTime");
    res.json({
      status: "Database Connected Successfully",
      time: result.recordset[0].currentTime
    });
  } catch (err) {
    res.status(500).json({
      error: "Database Connection Failed",
      details: err.message
    });
  }
});

// ================= BASIC HEALTH =================
app.get("/health", (req, res) => {
  res.json({ status: "Server Running" });
});

// ================= DEFAULT =================
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});