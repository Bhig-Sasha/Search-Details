require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { google } = require("googleapis");
const fs = require("fs");
const path = require("path");

const app = express();

// ===============================
// 🔧 Configuration
// ===============================
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "defaultsecret";
const SHEET_ID = process.env.USERS_SHEET_ID;

// ===============================
// 🔐 Load Google Service Account Key
// ===============================
let KEY = null;
try {
  const keyPath = path.join(__dirname, "GOOGLE_SERVICE_ACCOUNT_KEY.json");

  if (fs.existsSync(keyPath)) {
    KEY = JSON.parse(fs.readFileSync(keyPath, "utf8"));
    console.log("✅ Loaded service account key from file (local dev)");
  } else if (process.env.GOOGLE_SERVICE_ACCOUNT_KEY) {
    KEY = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_KEY);
    console.log("✅ Loaded service account key from environment variable (Render)");
  } else {
    throw new Error("No service account key found in file or environment");
  }
} catch (err) {
  console.error("❌ Could not load GOOGLE_SERVICE_ACCOUNT_KEY:", err.message);
  process.exit(1);
}

// ===============================
// 🧩 Middleware
// ===============================
app.use(cors({
  origin: [
    "https://student-details1.netlify.app",
    "http://127.0.0.1:5500",
    "http://localhost:5500"
  ],
}));
app.use(express.json());

// ===============================
// 📊 Google Sheets Setup
// ===============================
const auth = new google.auth.GoogleAuth({
  credentials: KEY,
  scopes: ["https://www.googleapis.com/auth/spreadsheets.readonly"],
});
const sheets = google.sheets({ version: "v4", auth });

// ===============================
// 🧠 Helper: Fetch users from Sheet
// ===============================
async function getUsers() {
  try {
    const res = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: "User_1!A:D", // Adjusted for your actual sheet name
    });

    const rows = res.data.values || [];
    if (rows.length < 2) {
      console.warn("⚠️ No user data found in sheet.");
      return [];
    }

    // Skip header row
    return rows.slice(1).map(([username, password, fullName, role]) => ({
      username: username?.trim(),
      password: password?.trim(),
      fullName: fullName?.trim() || username?.trim(),
      level: role?.trim() || "security",
    }));
  } catch (err) {
    console.error("❌ Error fetching users from sheet:", err.message);
    throw new Error("Failed to fetch users");
  }
}

// ===============================
// 🔑 Login Route
// ===============================
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Username and password required" });

  try {
    const users = await getUsers();
    const user = users.find(
      (u) =>
        u.username.toLowerCase() === username.toLowerCase() &&
        u.password === password
    );

    if (!user)
      return res.status(401).json({ message: "Invalid username or password" });

    const token = jwt.sign(
      {
        user: user.username,
        level: user.level,
        fullName: user.fullName,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      level: user.level,
      username: user.username,
      fullName: user.fullName,
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ message: "Server error during login" });
  }
});

// ===============================
// 🔒 Token Authentication Middleware
// ===============================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token)
    return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(401).json({ message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

// ===============================
// 🧾 Protected Route Example
// ===============================
app.get("/api/check", authenticateToken, (req, res) => {
  res.json({
    message: "Authorized",
    user: req.user.user,
    level: req.user.level,
    fullName: req.user.fullName,
  });
});

// ===============================
// 🧪 Test Sheet Connection
// ===============================
app.get("/api/test-users", async (req, res) => {
  try {
    const users = await getUsers();
    res.json({
      success: true,
      count: users.length,
      users,
    });
  } catch (err) {
    console.error("Error testing Google Sheet connection:", err.message);
    res.status(500).json({ success: false, message: "Failed to fetch users" });
  }
});

// ===============================
// 🚀 Start Server
// ===============================
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
