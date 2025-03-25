const express = require('express');
const axios = require('axios');
const app = express();

app.use(express.json());

const predictUrlSafety = async (url) => {
  try {
    //127.0.0.1 for local dev localhost for render
    //const response = await axios.post('http://127.0.0.1:5000/predict', { url });
    const response = await axios.post('http://localhost:5000/predict', { url })
    return response.data.phishing;
  } catch (error) {
    console.error('Prediction API error:', error.response ? error.response.data : error.message);
    throw new Error('Prediction failed');
  }
};

app.post('/api/check-url', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }
  try {
    const phishingStatus = await predictUrlSafety(url);
    res.json({ isSafe: phishingStatus === 'Safe' });
  } catch (error) {
    res.status(500).json({ error: 'Prediction failed', details: error.message });
  }
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});