// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();

// --- Configuration ---
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "defaultsecret";
const USERS_ENV = process.env.USERS || "admin:admin123:admin,security:pass123:security";

// --- Middleware ---
app.use(cors({
  origin: "https://student-details1.netlify.app" // your frontend URL
}));
app.use(express.json());

// --- Parse USERS from .env ---
const users = USERS_ENV.split(",").map(entry => {
  const [username, password, level] = entry.split(":");
  return {
    username: username.trim(),
    password: password.trim(),
    level: (level || "security").trim()
  };
});

// --- LOGIN ROUTE ---
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "Username and password required" });

  // Case-insensitive username match, exact password
  const user = users.find(u => u.username.toLowerCase() === username.toLowerCase() && u.password === password);

  if (!user) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  // Sign JWT with user info
  const token = jwt.sign(
    { user: user.username, level: user.level },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token, level: user.level });
});

// --- AUTH MIDDLEWARE ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid or expired token" });
    req.user = decoded; // attach user info to request
    next();
  });
}

// --- PROTECTED ROUTE ---
app.get("/api/check", authenticateToken, (req, res) => {
  res.json({ message: "Authorized", user: req.user.user, level: req.user.level });
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🛡️  JWT_SECRET is ${JWT_SECRET ? "set" : "not set"}`);
  console.log(`👥 Users loaded: ${users.map(u => `${u.username}(${u.level})`).join(", ")}`);
});
