require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const path = require("path");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

async function getDb() {
  return mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
  });
}

// Serve pages
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public/register.html"));
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public/login.html"));
});

// Registration handler
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const db = await getDb();
  try {
    await db.execute("INSERT INTO users(email, password_hash) VALUES(?, ?)", [
      email,
      hash,
    ]);
    res.redirect("/login");
  } catch (err) {
    res.send("Error: " + err.message);
  } finally {
    db.end();
  }
});

// Login handler
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const db = await getDb();
  const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [
    email,
  ]);
  db.end();

  if (rows.length && (await bcrypt.compare(password, rows[0].password_hash))) {
    res.send(`Welcome back, ${email}!`);
  } else {
    res.send("Invalid email or password");
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port}...`));
