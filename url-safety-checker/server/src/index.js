const express = require('express');
const axios = require('axios');
const cors = require('cors');
const dotenv = require('dotenv');
const { URL } = require('url');

// In-memory cache (for simplicity; use Redis in production)
const cache = new Map();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

app.use(cors());
app.use(express.json());

const checkUrlSafety = async (url) => {
  const cacheKey = `safety:${url}`;
  if (cache.has(cacheKey)) {
    const cached = cache.get(cacheKey);
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.data;
    }
    cache.delete(cacheKey);
  }

  try {
    const scanResponse = await axios.post(
      'https://www.virustotal.com/vtapi/v2/url/scan',
      `apikey=${VIRUSTOTAL_API_KEY}&url=${encodeURIComponent(url)}`,
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 5000 }
    );
    if (scanResponse.status !== 200) {
      return { status: 'error', message: `API error: ${scanResponse.status}` };
    }

    for (let i = 0; i < 5; i++) {
      const reportResponse = await axios.get(
        `https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${encodeURIComponent(url)}`,
        { timeout: 5000 }
      );
      const reportData = reportResponse.data;
      if (reportData.response_code === 1) {
        const result = {
          status: reportData.positives === 0 ? 'safe' : 'unsafe',
          positives: reportData.positives || 0,
          total_scans: reportData.total || 0,
        };
        cache.set(cacheKey, { data: result, timestamp: Date.now() });
        return result;
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    return { status: 'error', message: 'No scan results available' };
  } catch (e) {
    return { status: 'error', message: e.message };
  }
};

const checkRedirects = async (url) => {
  const cacheKey = `redirect:${url}`;
  if (cache.has(cacheKey)) {
    const cached = cache.get(cacheKey);
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.data;
    }
    cache.delete(cacheKey);
  }

  try {
    // Use a custom Axios instance to capture status codes
    const axiosInstance = axios.create({
      maxRedirects: 3,
      timeout: 5000,
      validateStatus: () => true,
    });

    // Intercept requests to capture status codes
    const statusCodes = [];
    let currentUrl = url;
    const redirectChain = [url];

    // Perform the request manually to track redirects
    let response = await axiosInstance.get(currentUrl);
    statusCodes.push(response.status);

    // Follow redirects manually to capture each status code
    while (response.status >= 300 && response.status < 400 && response.headers.location && redirectChain.length <= 3) {
      currentUrl = new URL(response.headers.location, currentUrl).toString();
      redirectChain.push(currentUrl);
      response = await axiosInstance.get(currentUrl);
      statusCodes.push(response.status);
    }

    // Log for debugging
    console.log(`URL: ${url}, Redirect chain: ${JSON.stringify(redirectChain)}, Status codes: ${JSON.stringify(statusCodes)}`);

    let result;
    if (redirectChain.length > 1) {
      // Check if the final URL is malicious
      const finalUrlSafety = await checkUrlSafety(redirectChain[redirectChain.length - 1]);
      const isFinalMalicious = finalUrlSafety.status === 'unsafe' && finalUrlSafety.positives > 0;

      result = {
        status: isFinalMalicious ? 'suspicious' : 'clean',
        redirect_chain: redirectChain,
        status_codes: statusCodes,
        final_url_safety: finalUrlSafety,
      };
    } else {
      // No redirects
      result = {
        status: 'clean',
        redirect_chain: redirectChain,
        status_codes: statusCodes,
        final_url_safety: { status: 'no_redirect' },
      };
    }

    // Log result for debugging
    console.log(`Result: ${JSON.stringify(result, null, 2)}`);

    cache.set(cacheKey, { data: result, timestamp: Date.now() });
    return result;
  } catch (e) {
    const result = {
      status: 'error',
      message: e.message,
      redirect_chain: [url],
      status_codes: [], // Ensure status_codes is always defined
      final_url_safety: { status: 'error' },
    };
    console.log(`Error: ${JSON.stringify(result, null, 2)}`);
    return result;
  }
};

const validateUrlStructure = (url) => {
  try {
    const parsed = new URL(url);
    return { status: 'valid', domain: parsed.hostname };
  } catch {
    return {
      status: 'invalid',
      message: 'Invalid URL format',
      redirect_chain: [url],
      status_codes: [],
      final_url_safety: { status: 'invalid' },
    };
  }
};

app.post('/check-urls', async (req, res) => {
  const { urls } = req.body;
  if (!urls || !Array.isArray(urls)) {
    return res.status(400).json({ error: 'Invalid input: URLs must be an array' });
  }

  const results = await Promise.all(
    urls.map(async (url) => {
      const structure = validateUrlStructure(url);
      if (structure.status === 'invalid') {
        return {
          url,
          structure,
          safety: { status: 'error', message: 'Invalid URL' },
          redirects: {
            status: 'error',
            message: 'Invalid URL',
            redirect_chain: [url],
            status_codes: [],
            final_url_safety: { status: 'invalid' },
          },
        };
      }

      const [safety, redirects] = await Promise.all([
        checkUrlSafety(url),
        checkRedirects(url),
      ]);

      return { url, structure, safety, redirects };
    })
  );

  res.json(results);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});