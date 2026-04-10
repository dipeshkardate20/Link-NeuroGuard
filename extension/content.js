chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scan_complete") {
    injectBanner(request.payload);
  }
});

function injectBanner(data) {
  if (document.getElementById('neuroguard-banner')) return;

  const isSafe = data.verdict === 'Safe';
  const isMalicious = data.verdict === 'Malicious';
  
  let bgColor = '#DC2626';
  if (isSafe) bgColor = '#10B981';
  else if (!isMalicious) bgColor = '#D97706';

  const emoji = isSafe ? '✅' : '🛡️';
  const alertText = isSafe ? 'NEUROGUARD CLEAR:' : 'NEUROGUARD ALERT:';

  const banner = document.createElement('div');
  banner.id = 'neuroguard-banner';
  
  banner.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    background-color: ${bgColor} !important;
    color: white !important;
    text-align: left !important;
    padding: 16px 24px !important;
    font-family: system-ui, -apple-system, sans-serif !important;
    font-size: 15px !important;
    z-index: 2147483647 !important; 
    box-shadow: 0 10px 25px rgba(0,0,0,0.5) !important;
    display: flex !important;
    justify-content: space-between !important;
    align-items: center !important;
    box-sizing: border-box !important;
    transition: transform 0.4s ease-in-out, opacity 0.4s ease-in-out !important;
  `;

  const textDiv = document.createElement('div');
  textDiv.innerHTML = `
    <span style="font-size: 20px; margin-right: 12px; vertical-align: middle;">${emoji}</span>
    <strong style="letter-spacing: 1px;">${alertText}</strong> 
    This domain is <strong>${data.xgb_prediction || data.verdict}</strong>. 
    <span style="opacity: 0.85; margin-left: 12px; font-style: italic;">"${data.reasoning}"</span>
  `;

  const closeBtn = document.createElement('button');
  closeBtn.innerText = 'Dismiss';
  closeBtn.style.cssText = `
    background: rgba(0,0,0,0.25) !important;
    border: 1px solid rgba(255,255,255,0.4) !important;
    color: white !important;
    padding: 8px 16px !important;
    border-radius: 6px !important;
    cursor: pointer !important;
    font-weight: bold !important;
    font-size: 13px !important;
    transition: background 0.2s !important;
  `;
  closeBtn.onmouseover = () => closeBtn.style.background = 'rgba(0,0,0,0.4)';
  closeBtn.onmouseout = () => closeBtn.style.background = 'rgba(0,0,0,0.25)';
  
  closeBtn.onclick = () => {
    banner.style.opacity = '0';
    setTimeout(() => banner.remove(), 400);
  };

  banner.appendChild(textDiv);
  banner.appendChild(closeBtn);
  const targetElement = document.body || document.documentElement;
  targetElement.prepend(banner);

  if (isSafe) {
    setTimeout(() => {
      if (document.body.contains(banner)) {
        banner.style.opacity = '0';
        banner.style.transform = 'translateY(-100%)';
        setTimeout(() => banner.remove(), 400);
      }
    }, 5500); 
  }
}