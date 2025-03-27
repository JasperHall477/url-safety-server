const express = require('express');
const axios = require('axios');
const path = require('path');
const cors = require('cors'); // Add CORS

const app = express();

// CORS configuration
app.use(cors({
  origin: (origin, callback) => {
    // Allow chrome-extension:// origins and web app
    const allowedOrigins = [
      'https://web-app-j994.onrender.com',
      'http://localhost:3000' // For local testing
    ];
    if (!origin || allowedOrigins.includes(origin) || origin.startsWith('chrome-extension://')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true
}));

app.use(express.json());
app.use(express.static('public'));

const predictUrlSafety = async (url) => {
  try {
    const flaskUrl = 'http://localhost:5000/predict';
    console.log(`Calling Flask API at: ${flaskUrl} with URL: ${url}`);
    const response = await axios.post(flaskUrl, { url });
    return response.data.phishing;
  } catch (error) {
    console.error('Prediction API error:', {
      message: error.message,
      response: error.response ? error.response.data : null,
      status: error.response ? error.response.status : null,
      code: error.code
    });
    throw new Error('Prediction failed');
  }
};

app.post('/api/check-url', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  try {
    const phishingStatus = await predictUrlSafety(url);
    res.json({ isSafe: phishingStatus === 'Safe' });
  } catch (error) {
    res.status(500).json({ error: 'Prediction failed', details: error.message });
  }
});

app.get('/checkURL', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'checkURL.html'));
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});