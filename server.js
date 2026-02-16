const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());

// Serve static files from /public folder
app.use(express.static(path.join(__dirname, 'public')));

// Health endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'API is healthy' });
});

// Books endpoint
app.get('/books', (req, res) => {
  res.json([
    { id: 1, title: 'Clean Code', author: 'Robert C. Martin' },
    { id: 2, title: 'Design Patterns', author: 'GoF' }
  ]);
});

// Home page (if someone goes to /)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
