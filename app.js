require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

async function getDb() {
  return mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
  });
}

// Health endpoint
app.get("/health", (_, res) => res.send("OK"));

// Dashboard
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// Register & Login pages
app.get("/register", (_, res) => {
  res.sendFile(path.join(__dirname, "public/register.html"));
});
app.get("/login", (_, res) => {
  res.sendFile(path.join(__dirname, "public/login.html"));
});

// Shopping page
app.get("/shopping", (req, res) => {
  res.sendFile(path.join(__dirname, "public/shopping.html"));
});

// Handle registration
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).send("Email & password required");

  const hash = await bcrypt.hash(password, 10);
  const db = await getDb();

  try {
    await db.execute("INSERT INTO users(email, password_hash) VALUES(?, ?)", [
      email,
      hash,
    ]);
    // Redirect with a flag for the popup
    res.redirect("/login?registered=1");
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

// Handle login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).send("Email & password required");

  const db = await getDb();
  try {
    const [rows] = await db.execute(
      "SELECT password_hash FROM users WHERE email = ?",
      [email]
    );
    if (
      !rows.length ||
      !(await bcrypt.compare(password, rows[0].password_hash))
    ) {
      return res.status(401).send("Invalid email or password");
    }
    // On success, redirect to shopping with the email in query
    res.redirect(`/shopping?email=${encodeURIComponent(email)}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  } finally {
    await db.end();
  }
});

// 404 catch-all
app.use((_, res) => res.status(404).send("Page not found"));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));
