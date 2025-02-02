// ✅ Debugging: Log every incoming request
app.use((req, res, next) => {
    console.log(`📥 Received request: ${req.method} ${req.url}`);
    next();
});

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { Pool } = require("pg");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config({ path: "./.env" });

console.log("NEWS_API_KEY:", process.env.NEWS_API_KEY);
console.log("FACT_CHECK_API_KEY:", process.env.FACT_CHECK_API_KEY);
console.log("DATABASE_URL:", process.env.DATABASE_URL);
console.log("JWT_SECRET:", process.env.JWT_SECRET);

const app = express();
app.use(cors());
app.use(express.json());
app.use(helmet());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
});
app.use(limiter);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

const NEWS_API_URL = "https://newsapi.org/v2/top-headlines";
const FACT_CHECK_API_URL =
    "https://factchecktools.googleapis.com/v1alpha1/claims:search";

// User authentication
app.post("/api/register", async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (username, password) VALUES ($1, $2)",
            [username, hashedPassword]
        );
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ error: "Failed to register user" });
    }
});

app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await pool.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );
        if (user.rows.length === 0)
            return res.status(401).json({ error: "Invalid credentials" });

        const validPassword = await bcrypt.compare(
            password,
            user.rows[0].password
        );
        if (!validPassword)
            return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign({ username }, process.env.JWT_SECRET, {
            expiresIn: "1h",
        });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: "Failed to login" });
    }
});

// Middleware for authentication
const authenticate = (req, res, next) => {
    console.log("🔹 Received Authorization Header:", req.headers["authorization"]);

    const token = req.headers["authorization"];
    if (!token) {
        console.log("❌ No token received");
        return res.status(403).json({ error: "Access denied" });
    }

    const tokenValue = token.split(" ")[1];
    console.log("🟢 Extracted Token:", tokenValue);

    jwt.verify(tokenValue, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.log("❌ JWT Verification Error:", err.message);
            return res.status(403).json({ error: "Invalid token" });
        }
        console.log("✅ Token Verified! User:", user);
        req.user = user;
        next();
    });
};

// Fetch live news
app.get("/api/news", authenticate, async (req, res) => {
    try {
        const { data } = await axios.get(NEWS_API_URL, {
            params: { country: "us", apiKey: process.env.NEWS_API_KEY },
        });
        res.json(data.articles);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch news" });
    }
});

// Fact-check news and store results
app.get("/api/fact-check", authenticate, async (req, res) => {
    try {
        const { query } = req.query;
        const { data } = await axios.get(FACT_CHECK_API_URL, {
            params: { query, key: process.env.FACT_CHECK_API_KEY },
        });

        const claims = data.claims || [];
        for (const claim of claims) {
            await pool.query(
                "INSERT INTO fact_checks (query, text, source) VALUES ($1, $2, $3) ON CONFLICT (text) DO NOTHING",
                [query, claim.text, claim.claimReview[0]?.publisher?.name || "Unknown"]
            );
        }

        res.json(claims);
    } catch (error) {
        res.status(500).json({ error: "Failed to verify news" });
    }
});

// ✅ Port Fix: Ensure the server listens on Render’s assigned port
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});

// ✅ Debugging: Log every incoming request
app.use((req, res, next) => {
    console.log(`📥 Received request: ${req.method} ${req.url}`);
    next();
});

// ✅ Root endpoint for testing
app.get("/", (req, res) => {
    console.log("✅ Root endpoint hit - Sending response"); // Log for debugging
    res.status(200).send("✅ API is running..."); // Ensure a proper response is sent
});


