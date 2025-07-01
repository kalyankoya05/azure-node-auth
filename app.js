require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

// parse URL-encoded bodies (form posts)
app.use(express.urlencoded({ extended: false }));

// serve all files in /public
app.use(express.static(path.join(__dirname, "public")));

// Health check endpoint
app.get("/health", (_, res) => {
  res.status(200).send("OK");
});

// Dashboard route (default page)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Registration page
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

// Login page
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Get a new DB connection
async function getDb() {
  return mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
  });
}

// Handle registration form POST
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email and password required");
  }

  const hash = await bcrypt.hash(password, 10);
  const db = await getDb();
  try {
    await db.execute("INSERT INTO users(email, password_hash) VALUES(?, ?)", [
      email,
      hash,
    ]);
    res.redirect("/login");
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      res.status(409).send("Email already registered");
    } else {
      console.error(err);
      res.status(500).send("Server error");
    }
  } finally {
    await db.end();
  }
});

// Handle login form POST
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email and password required");
  }

  const db = await getDb();
  try {
    const [rows] = await db.execute(
      "SELECT password_hash FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res.status(401).send("Invalid email or password");
    }

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) {
      return res.status(401).send("Invalid email or password");
    }

    res.send(`Welcome back, ${email}!`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  } finally {
    await db.end();
  }
});

// 404 for any other routes
app.use((_, res) => {
  res.status(404).send("Page not found");
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Listening on port ${port}...`);
});
