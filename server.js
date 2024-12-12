require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const multer = require("multer");
const connection = require("./db");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const dbHost = process.env.DB_HOST;
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;
const jwtSecret = process.env.JWT_SECRET;

console.log("DB_HOST:", dbHost);
console.log("DB_USER:", dbUser);
console.log("DB_PASS:", dbPass);
console.log("JWT_SECRET:", jwtSecret);

const app = express();
const PORT = 3000;

app.use(cors());
app.use("/uploads", express.static("uploads"));
app.use(bodyParser.json({ limit: "50mb" })); // Increase to 50MB
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

app.use(express.json({ limit: "50mb" }));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage: storage });

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user; // Menyimpan data user dari token
    next();
  });
}

app.get("/users", (req, res) => {
  connection.query("SELECT * FROM users", (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Server error");
    }
    return res.status(200).json(results);
  });
});

app.get("/users/:id", (req, res) => {
  const { id } = req.params;
  connection.query(
    "SELECT id, username, email, first_name, last_name, photo_url FROM users WHERE id = ?",
    [id],
    (err, results) => {
      if (err) {
        console.error("Error fetching user data: ", err);
        return res.status(500).send("Server error");
      }
      if (results.length === 0) {
        return res.status(404).send("User not found");
      }
      res.json(results[0]);
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Validasi input
  if (!username || !password) {
    return res
      .status(400)
      .send({ message: "Username and password are required" });
  }

  const query = "SELECT * FROM users WHERE username = ?";
  connection.query(query, [username], (err, results) => {
    if (err) {
      console.error("Error during login: ", err);
      return res.status(500).send("Server error");
    }

    if (results.length === 0) {
      return res.status(401).send({ message: "Invalid username or password" });
    }

    const user = results[0];

    // Periksa kecocokan password terenkripsi dengan bcrypt
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Error comparing passwords: ", err);
        return res.status(500).send("Error comparing passwords");
      }

      if (!isMatch) {
        return res
          .status(401)
          .send({ message: "Invalid username or password" });
      }

      // Jika password cocok, buat token JWT
      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: "1h" } // Token berlaku selama 1 jam
      );

      // Kirimkan user_id, username, photo_url, dan token ke dalam response
      return res.json({
        message: "Login successful",
        user_id: user.id, // Tambahkan user_id dari database
        token: token, // Token JWT
        username: user.username, // Username
        photo_url: user.photo_url, // URL foto profil dari kolom photo_path
      });
    });
  });
});

app.post("/register", upload.single("photo"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Photo is required" });
    }
    const { username, email, password, first_name, last_name } = req.body;
    const photo_path = req.file.path;

    const hashedPassword = await bcrypt.hash(password, 10);
    connection.query(
      "INSERT INTO users (username, email, password, first_name, last_name, photo_url) VALUES (?, ?, ?, ?, ?, ?)",
      [username, email, hashedPassword, first_name, last_name, photo_path],
      (err) => {
        if (err) {
          console.error(err);
          return res.status(500).send("Server error");
        }
        res.status(201).json({ message: "User registered successfully" });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

// app.post("/add-item", authenticateToken, (req, res) => {
//   const {
//     name,
//     stock,
//     location,
//     condition,
//     reminder_date,
//     image_path,
//     description,
//   } = req.body;

//   // Validate the input fields
//   if (
//     !name ||
//     !stock ||
//     !location ||
//     !condition ||
//     !reminder_date ||
//     !image_path ||
//     !description
//   ) {
//     return res.status(400).send({ message: "All fields are required" });
//   }

//   // Get the user ID from the authenticated token
//   const userId = req.user.id;

//   // Prepare the query to insert the item, associating it with the logged-in user
//   const query = `
//     INSERT INTO items (name, stock, location, \`condition\`, reminder_date, image_path, description, user_id)
//     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
//   `;

//   // Execute the query to insert the item
//   connection.query(
//     query,
//     [
//       name,
//       stock,
//       location,
//       condition,
//       reminder_date,
//       image_path,
//       description,
//       userId, // Store the user ID for the logged-in user
//     ],
//     (err, results) => {
//       if (err) {
//         console.error(err);
//         return res.status(500).send("Server error");
//       }
//       // You can return results or just a success message
//       console.log(results); // Optional: Log the results to the console

//       return res.status(201).json({
//         message: "Item added successfully",
//         itemId: results.insertId, // You can also send back the inserted item's ID
//       });
//     }
//   );
// });

// Endpoint untuk menambahkan item
// app.post(
//   "/add-item",
//   authenticateToken,
//   upload.single("image_path"),
//   (req, res) => {
//     const { name, stock, location, condition, reminder_date, description } =
//       req.body;
//     const imagePath = req.file ? req.file.path : null; // Pastikan file image sudah ada

//     // Validasi inputan
//     if (
//       !name ||
//       !stock ||
//       !location ||
//       !condition ||
//       !reminder_date ||
//       !imagePath ||
//       !description
//     ) {
//       return res.status(400).json({ message: "All fields are required" });
//     }

//     const userId = req.user.id; // Mendapatkan user ID dari token yang sudah terautentikasi

//     // Query untuk menyimpan item ke database
//     const query = `
//     INSERT INTO items (name, stock, location, \`condition\`, reminder_date, image_path, description, user_id)
//     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
//   `;

//     connection.query(
//       query,
//       [
//         name,
//         stock,
//         location,
//         condition,
//         reminder_date,
//         imagePath,
//         description,
//         userId,
//       ],
//       (err, results) => {
//         if (err) {
//           console.error(err);
//           return res.status(500).json({ message: "Server error" });
//         }
//         return res.status(201).json({
//           message: "Item added successfully",
//           itemId: results.insertId,
//         });
//       }
//     );
//   }
// );

app.post(
  "/add-item",
  authenticateToken,
  upload.single("image_path"),
  (req, res) => {
    const { name, stock, location, condition, reminder_date, description } =
      req.body;
    const imagePath = req.file ? req.file.path : null; // Pastikan file image sudah ada

    // Validasi inputan
    if (
      !name ||
      !stock ||
      !location ||
      !condition ||
      !reminder_date ||
      !imagePath ||
      !description
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const userId = req.user.id; // Mendapatkan user ID dari token yang sudah terautentikasi

    // Membuat URL lengkap untuk gambar yang disimpan
    const imageUrl = `http://192.168.1.2:3000/${imagePath.replace(
      "uploads/",
      ""
    )}`;

    // Query untuk menyimpan item ke database
    const query = `
    INSERT INTO items (name, stock, location, \`condition\`, reminder_date, image_path, description, user_id) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;

    connection.query(
      query,
      [
        name,
        stock,
        location,
        condition,
        reminder_date,
        imageUrl, // Simpan URL penuh gambar, bukan hanya path
        description,
        userId,
      ],
      (err, results) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: "Server error" });
        }
        return res.status(201).json({
          message: "Item added successfully",
          itemId: results.insertId,
        });
      }
    );
  }
);

app.get("/items", authenticateToken, (req, res) => {
  const userId = req.user.id; // user id didapat dari JWT
  const query = "SELECT * FROM items WHERE user_id = ?";

  connection.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching items:", err);
      return res.status(500).json({ error: "Error fetching items" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "No items found" });
    }

    res.json(results);
  });
});

app.get("/items/search", authenticateToken, (req, res) => {
  const userId = req.user.id; // user id didapat dari JWT
  const searchQuery = req.query.query; // Mendapatkan query pencarian dari parameter URL

  if (!searchQuery) {
    return res.status(400).json({ message: "Search query is required" });
  }

  const query = "SELECT * FROM items WHERE user_id = ? AND name LIKE ?";
  connection.query(query, [userId, `%${searchQuery}%`], (err, results) => {
    if (err) {
      console.error("Error fetching items:", err);
      return res.status(500).json({ error: "Error fetching items" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "No items found" });
    }

    res.json(results); // Mengirimkan hasil pencarian item
  });
});

// Endpoint untuk mengambil item spesifik sesuai user dan item ID
app.get("/items/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  const query = "SELECT * FROM items WHERE id = ? AND user_id = ?";

  connection.query(query, [id, userId], (err, results) => {
    if (err) {
      console.error("Error fetching item from database:", err);
      return res.status(500).json({ error: "Server error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "Item not found" });
    }

    res.json(results[0]);
  });
});

// 5. Hapus Item (Hanya milik user yang login)
app.delete("/items/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const query = "DELETE FROM items WHERE id = ? AND user_id = ?";
  connection.query(query, [id, userId], (err, results) => {
    if (err) {
      console.error("Error deleting item from database: ", err);
      return res.status(500).send("Server error");
    }

    if (results.affectedRows === 0) {
      return res.status(404).send("Item not found");
    }

    res.status(200).json({ message: "Item deleted successfully" });
  });
});

// Edit Item (Hanya milik user yang login)
app.put(
  "/items/:id",
  authenticateToken,
  upload.single("image_path"),
  (req, res) => {
    const { id } = req.params; // ID item yang akan diedit
    const userId = req.user.id; // ID user yang login dari token autentikasi

    // Data item yang akan diperbarui
    const { name, stock, location, condition, reminder_date, description } =
      req.body;

    // Pastikan gambar yang di-upload diambil
    const imagePath = req.file ? req.file.path : null;

    // Validasi inputan
    if (
      !name ||
      stock === undefined ||
      !location ||
      !condition ||
      !reminder_date ||
      !imagePath ||
      !description
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Membuat URL lengkap untuk gambar yang disimpan
    const imageUrl = `http://192.168.1.2:3000/${imagePath.replace(
      "uploads/",
      ""
    )}`;

    // Query untuk memperbarui data item berdasarkan id dan user_id
    const query = `
    UPDATE items 
    SET 
      name = ?, 
      stock = ?, 
      location = ?, 
      \`condition\` = ?, 
      reminder_date = ?, 
      image_path = ?, 
      description = ? 
    WHERE id = ? AND user_id = ?
  `;

    const queryParams = [
      name,
      stock,
      location,
      condition,
      reminder_date,
      imageUrl, // Simpan URL gambar, bukan hanya path
      description,
      id,
      userId,
    ];

    connection.query(query, queryParams, (err, results) => {
      if (err) {
        console.error("Error updating item in database: ", err);
        return res.status(500).send("Server error");
      }

      if (results.affectedRows === 0) {
        return res
          .status(404)
          .send("Item not found or you do not have permission to edit it");
      }

      res.status(200).json({ message: "Item updated successfully" });
    });
  }
);

// Endpoint to add an item to favorites
app.post("/favorites", authenticateToken, (req, res) => {
  const userId = req.user.id; // user id from JWT
  const { itemId } = req.body; // ID of the item to be added to favorites

  if (!itemId) {
    return res.status(400).json({ message: "Item ID is required" });
  }

  // Query to check if the item already exists in the user's favorites
  const checkQuery =
    "SELECT * FROM favorites WHERE user_id = ? AND item_id = ?";
  connection.query(checkQuery, [userId, itemId], (err, results) => {
    if (err) {
      console.error("Error checking favorite:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (results.length > 0) {
      return res
        .status(400)
        .json({ message: "Item is already in your favorites" });
    }

    // If the item is not already in favorites, insert it
    const query = "INSERT INTO favorites (user_id, item_id) VALUES (?, ?)";
    connection.query(query, [userId, itemId], (err, results) => {
      if (err) {
        console.error("Error adding to favorites:", err);
        return res.status(500).json({ message: "Server error" });
      }

      res.status(201).json({ message: "Item added to favorites" });
    });
  });
});

// Endpoint to get all favorite items for a user
app.get("/favorites", authenticateToken, (req, res) => {
  const userId = req.user.id; // user id from JWT

  const query = `
    SELECT items.* FROM items
    JOIN favorites ON items.id = favorites.item_id
    WHERE favorites.user_id = ?
  `;

  connection.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching favorite items:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "No favorite items found" });
    }

    res.json(results); // Send back all the favorite items
  });
});

// Endpoint to remove an item from favorites
app.delete("/favorites/:itemId", authenticateToken, (req, res) => {
  const userId = req.user.id; // user id from JWT
  const { itemId } = req.params; // ID of the item to be removed

  // Query to delete the item from the user's favorites
  const query = "DELETE FROM favorites WHERE user_id = ? AND item_id = ?";
  connection.query(query, [userId, itemId], (err, results) => {
    if (err) {
      console.error("Error removing from favorites:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (results.affectedRows === 0) {
      return res
        .status(404)
        .json({ message: "Item not found in your favorites" });
    }

    res.status(200).json({ message: "Item removed from favorites" });
  });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
