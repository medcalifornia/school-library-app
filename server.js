const express = require("express");
const path = require("path");

const app = express();
app.use(express.json());

// Serve the frontend from /public
app.use(express.static(path.join(__dirname, "public")));

// In-memory "database"
let books = [
  { id: 1, title: "Clean Code", author: "Robert C. Martin" },
  { id: 2, title: "Design Patterns", author: "GoF" }
];
let nextId = 3;

// Health endpoint (good for Azure Health Check)
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "API is healthy" });
});

// GET all books
app.get("/api/books", (req, res) => {
  res.json(books);
});

// POST new book
app.post("/api/books", (req, res) => {
  const { title, author } = req.body;

  if (!title || !author) {
    return res.status(400).json({ error: "title and author are required" });
  }

  const newBook = { id: nextId++, title: title.trim(), author: author.trim() };
  books.push(newBook);
  res.status(201).json(newBook);
});

// DELETE a book by id
app.delete("/api/books/:id", (req, res) => {
  const id = Number(req.params.id);
  const before = books.length;
  books = books.filter(b => b.id !== id);

  if (books.length === before) {
    return res.status(404).json({ error: "Book not found" });
  }

  res.json({ status: "OK", deletedId: id });
});

// Home route -> send UI
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
