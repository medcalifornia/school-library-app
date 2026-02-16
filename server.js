const express = require('express');
const app = express();

app.use(express.json());

// ✅ Root route (so / doesn't show "Cannot GET /")
app.get('/', (req, res) => {
  res.send('Library API is running 🚀');
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'API is healthy' });
});

app.get('/books', (req, res) => {
  res.json([
    { id: 1, title: 'Clean Code', author: 'Robert C. Martin' },
    { id: 2, title: 'Design Patterns', author: 'GoF' }
  ]);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
