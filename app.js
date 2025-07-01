require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const path = require("path");
const session = require("express-session");

const app = express();

// parse URL-encoded bodies
app.use(express.urlencoded({ extended: false }));

// session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "replace-with-strong-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 }, // 1 hour
  })
);

// serve static files from /public
app.use(express.static(path.join(__dirname, "public")));

// helper to get a DB connection
async function getDb() {
  return mysql.createConnection({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    ssl: {
      // allow TLS to Azure MySQL
      rejectUnauthorized: true,
    },
    connectTimeout: 10000, // 10 seconds
  });
}

// Health check
app.get("/health", (_, res) => res.status(200).send("OK"));

// Dashboard (default page)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// Registration page
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public/register.html"));
});

// Login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public/login.html"));
});

// Shopping page (protected)
app.get("/shopping", (req, res) => {
  if (!req.session.userEmail) {
    return res.redirect("/login");
  }
  res.sendFile(path.join(__dirname, "public/shopping.html"));
});

// POST /register
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email and password are required.");
  }

  const hash = await bcrypt.hash(password, 10);
  const db = await getDb();
  try {
    await db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", [
      email,
      hash,
    ]);
    // on success, redirect to login with a flag
    res.redirect("/login?registered=1");
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      res.status(409).send("That email is already registered.");
    } else {
      console.error(err);
      res.status(500).send("Server error.");
    }
  } finally {
    await db.end();
  }
});

// POST /login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email and password are required.");
  }

  const db = await getDb();
  try {
    const [rows] = await db.execute(
      "SELECT password_hash FROM users WHERE email = ?",
      [email]
    );
    if (!rows.length) {
      return res.status(401).send("Invalid email or password.");
    }
    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) {
      return res.status(401).send("Invalid email or password.");
    }

    // store user in session
    req.session.userEmail = email;
    res.redirect("/shopping");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error.");
  } finally {
    await db.end();
  }
});

// Logout endpoint
app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// 404 fallback
app.use((_, res) => res.status(404).send("Page not found."));

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Listening on port ${port}...`);
});
