const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const dotenv = require("dotenv");
dotenv.config();

const port = process.env.ACCREDIAN_SERVER_PORT;
const app = express();

app.use(bodyParser.json());
app.use(cors());

const db = mysql.createConnection({
  host: process.env.MYSQL_ACCREDIAN_DB_HOST,
  user: process.env.MYSQL_ACCREDIAN_DB_USER,
  password: process.env.MYSQL_ACCREDIAN_DB_PASSWORD,
  database: process.env.MYSQL_ACCREDIAN_DB_DATABASE,
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL");
});

const jwtSecret = "1234567890";

app.post("/signup", async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  const sql_find_user = "SELECT * FROM users WHERE email = ? OR username = ?";
  db.query(sql_find_user, [email, username], async (err, result) => {
    if (err) {
      console.log("database selection error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    console.log("result", result);
    if (result.length == 0) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const sql =
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
      db.query(sql, [username, email, hashedPassword], (err, result) => {
        if (err) {
          console.error("Database insertion error:", err);
          return res.status(500).json({ error: "Internal Server Error" });
        }
        return res
          .status(201)
          .json({ message: "User registered successfully" });
      });
    } else {
      console.log("username or email is already used");
      return res
        .status(403)
        .json({ error: "username or email is already used" });
    }
  });
});

app.post("/login", async (req, res) => {
  const { usernameOrEmail, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ? OR username = ?";
  db.query(sql, [usernameOrEmail, usernameOrEmail], async (err, result) => {
    if (err) {
      console.error("Database selection error:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    console.log(result);
    if (result.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, jwtSecret, {
      expiresIn: "1h",
    });

    return res.status(200).json({ message: "Login successful", token });
  });
});

app.use((err, req, res, next) => {
  console.error("Error:", err);
  res.status(500).json({ error: "Internal Server Error" });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
