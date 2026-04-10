document.addEventListener('DOMContentLoaded', async () => {
  const urlInput = document.getElementById('target-url');
  const scanBtn = document.getElementById('scan-btn');
  const resultsArea = document.getElementById('results-area');
  const verdictBadge = document.getElementById('verdict-badge');
  const threatType = document.getElementById('threat-type');
  const confidence = document.getElementById('confidence');
  const reasoning = document.getElementById('reasoning');

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    let currentUrl = tabs[0].url;
    if (currentUrl.startsWith('http')) {
      urlInput.value = currentUrl;
    } else {
      urlInput.value = "System Page (Cannot Scan)";
      scanBtn.disabled = true;
    }
  });

  scanBtn.addEventListener('click', async () => {
    const target = urlInput.value;
    if (!target || target === "System Page (Cannot Scan)") return;

    scanBtn.innerText = "Analyzing Neural Patterns...";
    scanBtn.disabled = true;
    resultsArea.classList.add('hidden');
    resultsArea.className = 'card';

    try {
      const API_URL = 'https://localhost:8000/analyze';
      
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Analysis failed");

      resultsArea.classList.remove('hidden');
      
      const isSafe = data.verdict === 'Safe';
      const isSuspicious = data.verdict === 'Suspicious';

      verdictBadge.innerText = data.verdict;
      threatType.innerText = isSafe ? 'Clean / Trusted' : (data.xgb_prediction || 'Suspicious Activity');
      confidence.innerText = `${data.xgb_confidence || 100}% Confidence`;
      reasoning.innerText = `"${data.reasoning}"`;
      
      const reasoningContainer = document.querySelector('.reasoning-container');

      if (isSafe) {
        resultsArea.classList.add('status-safe');
        document.body.style.height = '340px'; 
        reasoningContainer.style.display = 'none'; 
      } else {
        if (isSuspicious) resultsArea.classList.add('status-suspicious');
        else resultsArea.classList.add('status-malicious');
        
        document.body.style.height = '480px';
        reasoningContainer.style.display = 'block';
      }

    } catch (error) {
      resultsArea.classList.remove('hidden');
      resultsArea.classList.add('status-malicious');
      threatType.innerText = "Connection Failed";
      reasoning.innerText = `Engine Error: ${error.message}`;
      verdictBadge.innerText = "ERR";
    } finally {
      scanBtn.innerText = "Analyze Target";
      scanBtn.disabled = false;
    }
  });
});