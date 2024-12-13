const mysql = require("mysql");

const connection = mysql.createConnection({
  host: "localhost",
  user: "root", // Ganti dengan username database Anda
  password: "", // Ganti dengan password database Anda
  database: "project_homeinventory", // Ganti dengan nama database Anda
});

connection.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.stack);
    return;
  }
  console.log("Connected to database.");
});

module.exports = connection;
