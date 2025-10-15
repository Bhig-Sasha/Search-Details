require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();

// --- Configuration ---
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "defaultsecret";
const USERS_ENV = process.env.USERS;

// --- CORS Setup ---
const allowedOrigins = [
  "https://student-details1.netlify.app",
  "http://127.0.0.1:5500",
  "http://localhost:5500"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) callback(null, true);
      else {
        console.warn("❌ CORS blocked origin:", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use(express.json());

// --- Parse USERS from .env ---
const users = USERS_ENV.split(",").map(entry => {
  const [username, password, fullname, level] = entry.split(":");
  return {
    username: (username || "").trim(),
    password: (password || "").trim(),
    fullname: (fullname || "").trim(),
    level: (level || "security").trim(),
  };
});

// --- LOGIN ROUTE ---
app.post("/api/auth/login", (req, res) => {
  try {
    const { username, password } = req.body;
      console.log("🟡 Incoming login:", username, password); 
      console.log("🧩 Available users:", users); 

    if (!username || !password)
      return res.status(400).json({ message: "Username and password required" });

    const user = users.find(
      u =>
        u.username.trim().toLowerCase() === username.trim().toLowerCase() &&
        u.password.trim() === password.trim()
    );

    if (!user)
      return res.status(401).json({ message: "Invalid username or password" });

    const token = jwt.sign(
      { user: user.username, level: user.level },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // ✅ Send consistent field names
    res.json({
      token,
      username: user.username,
      fullname: user.fullname,
      userLevel: user.level,
    });

    console.log("✅ Sent to frontend:", {
      username: user.username,
      fullname: user.fullname,
      userLevel: user.level
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- AUTH MIDDLEWARE ---
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

// --- PROTECTED ROUTE ---
app.get("/api/check", authenticateToken, (req, res) => {
  res.json({
    message: "Authorized",
    user: req.user.user,
    level: req.user.level,
  });
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`👥 Users loaded: ${users.map(u => `${u.username}(${u.level})`).join(", ")}`);
});
