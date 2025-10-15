// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

// Import fetch dynamically (for CommonJS)
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();

// ==================== CONFIGURATION ====================
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "defaultsecret";

// 🔹 Your SheetDB login database
const LOGIN_SHEETDB_URL = "https://sheetdb.io/api/v1/a35j8mg76r4oo";

// ==================== MIDDLEWARE ====================
app.use(express.json());

const allowedOrigins = [
  "https://student-details1.netlify.app",
  "http://127.0.0.1:5500",
  "http://localhost:5500",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) callback(null, true);
      else {
        console.warn("❌ CORS blocked origin:", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

// ==================== LOGIN ROUTE ====================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ message: "Username and password required" });

    // 🔍 Fetch user from SheetDB
    const response = await fetch(
      `${LOGIN_SHEETDB_URL}/search?username=${encodeURIComponent(username)}`
    );
    const users = await response.json();

    console.log("🟡 SheetDB login response:", users);

    if (!Array.isArray(users) || users.length === 0)
      return res.status(401).json({ message: "Invalid username or password" });

    const user = users[0];

    // ✅ Normalize SheetDB fields
    const uname = user.username || user.Username || "";
    const pass = user.password || user.Password || "";
    const fullname = user.fullname || user.Fullname || user["Full Name"] || uname;
    const role = user.role || user.Role || user.userLevel || "Security";

    // 🔑 Password check
    if (pass !== password)
      return res.status(401).json({ message: "Invalid username or password" });

    console.log(`✅ Login successful: ${uname} (${role}) — ${fullname}`);

    // 🎟️ Generate JWT token
    const token = jwt.sign(
      { user: uname, level: role },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    // 🎯 Return to frontend
    res.json({
      token,
      username: uname,
      fullname: fullname,
      userLevel: role,
      message: `Welcome ${fullname}`,
    });
  } catch (err) {
    console.error("💥 Login error:", err);
    res.status(500).json({ message: "Server error occurred" });
  }
});

// ==================== AUTH MIDDLEWARE ====================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

// ==================== CHECK ROUTE ====================
app.get("/api/check", authenticateToken, (req, res) => {
  res.json({
    message: "Authorized",
    user: req.user.user,
    level: req.user.level,
  });
});

// ==================== SERVER START ====================
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🔗 Connected to SheetDB for login authentication`);
});
