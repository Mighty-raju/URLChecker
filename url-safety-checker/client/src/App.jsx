import { useState } from 'react';

function App() {
  const [urls, setUrls] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);

  const BATCH_SIZE = 1; // Process 10 URLs at a time

  const handleCheckUrls = async () => {
    setLoading(true);
    setError('');
    setResults([]);
    setProgress(0);

    const urlList = urls.split('\n').map(url => url.trim()).filter(url => url);
    if (urlList.length === 0) {
      setError('Please enter at least one URL');
      setLoading(false);
      return;
    }

    try {
      const batches = [];
      for (let i = 0; i < urlList.length; i += BATCH_SIZE) {
        batches.push(urlList.slice(i, i + BATCH_SIZE));
      }

      const allResults = [];
      for (let i = 0; i < batches.length; i++) {
        const batch = batches[i];
        const response = await fetch('http://localhost:5000/check-urls', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ urls: batch }),
        });
        const data = await response.json();
        allResults.push(...data);
        setResults([...allResults]);
        setProgress(((i + 1) / batches.length) * 100);
      }
    } catch (e) {
      setError('Failed to check URLs: ' + e.message);
    } finally {
      setLoading(false);
      setProgress(100);
    }
  };

  return (
    <div className="max-w-7xl mx-auto p-6 bg-white rounded-lg shadow-lg min-h-screen">
      <h1 className="text-2xl font-bold mb-4 text-center">URL Safety Checker</h1>
      <p className="text-gray-600 mb-4">Enter URLs (one per line) to check for safety and redirects.</p>
      <textarea
        className="w-full p-2 border rounded-md mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
        rows="5"
        placeholder="https://example.com\nhttp://test.com"
        value={urls}
        onChange={(e) => setUrls(e.target.value)}
      />
      <button
        className={`w-full py-2 px-4 bg-blue-500 text-white rounded-md hover:bg-blue-600 ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
        onClick={handleCheckUrls}
        disabled={loading}
      >
        {loading ? 'Checking...' : 'Check URLs'}
      </button>
      {loading && (
        <div className="mt-4">
          <div className="w-full bg-gray-200 rounded-full h-2.5">
            <div
              className="bg-blue-500 h-2.5 rounded-full"
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          <p className="text-sm text-gray-600 mt-1">Progress: {Math.round(progress)}%</p>
        </div>
      )}
      {error && <p className="text-red-500 mt-2">{error}</p>}
      {results.length > 0 && (
        <div className="mt-6 overflow-x-auto">
          <table className="min-w-full border-collapse border border-gray-300">
            <thead>
              <tr className="bg-gray-100">
                <th className="border border-gray-300 px-4 py-2 text-left text-sm font-semibold text-gray-700">URL</th>
                <th className="border border-gray-300 px-4 py-2 text-left text-sm font-semibold text-gray-700">Flagged as Malicious</th>
                <th className="border border-gray-300 px-4 py-2 text-left text-sm font-semibold text-gray-700">Malicious Redirects</th>
              </tr>
            </thead>
            <tbody>
              {results.map((result, index) => (
                <tr key={index} className={index % 2 === 0 ? 'bg-white' : 'bg-gray-50'}>
                  <td className="border border-gray-300 px-4 py-2 text-sm text-gray-600 truncate max-w-xs" title={result.url}>
                    {result.url}
                  </td>
                  <td className="border border-gray-300 px-4 py-2 text-sm text-gray-600">
                    {result.safety.status ? (result.safety.positives > 0 ? 'Yes' : 'No') : 'N/A'}
                    {result.safety.message && <span className="text-red-500"> ({result.safety.message})</span>}
                  </td>
                  <td className="border border-gray-300 px-4 py-2 text-sm text-gray-600">
                    {result.redirects.status && result.redirects.status_codes
                      ? (result.redirects.status === 'suspicious'
                          ? `Yes (Status codes: ${result.redirects.status_codes.join(', ')})`
                          : `No (Status codes: ${result.redirects.status_codes.join(', ')})`)
                      : 'N/A'}
                    {result.redirects.message && <span className="text-red-500"> ({result.redirects.message})</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default App;