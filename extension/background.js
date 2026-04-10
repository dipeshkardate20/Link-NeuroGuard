const API_URL = 'https://localhost:8000/analyze';

function deliverPayloadWithRetry(tabId, message, retries = 5) {
  chrome.tabs.sendMessage(tabId, message, (response) => {
    if (chrome.runtime.lastError) {
      if (retries > 0) {
        setTimeout(() => deliverPayloadWithRetry(tabId, message, retries - 1), 500);
      }
    }
  });
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('http')) {
    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url })
      });

      const data = await response.json();
      if (!response.ok) return;
      deliverPayloadWithRetry(tabId, {
        action: "scan_complete", 
        payload: data
      }); 
      
    } catch (error) {
      console.error("NeuroGuard Background Error:", error);
    }
  }
});