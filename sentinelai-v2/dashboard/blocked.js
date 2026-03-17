const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url') || 'Unknown URL';
const score = params.get('score') || '90+';
const threat = params.get('threat') || 'Heuristic Match or Threat Intel Hit';

document.getElementById('target-url').textContent = blockedUrl;
document.getElementById('risk-score').textContent = score;

let decodedThreat = decodeURIComponent(threat);
if (decodedThreat.includes('{')) {
  try {
    const threatObj = JSON.parse(decodedThreat);
    decodedThreat = threatObj.detail || threatObj.type || decodedThreat;
  } catch(e) {}
}
document.getElementById('primary-threat').textContent = decodedThreat;

document.getElementById('btn-back').addEventListener('click', () => {
  if (window.history.length > 2) {
    window.history.go(-2);
    return;
  }

  window.close();
});

document.getElementById('btn-proceed').addEventListener('click', () => {
  try {
    const urlObj = new URL(blockedUrl);
    chrome.runtime.sendMessage(
      {
        type: 'SENTINEL_WHITELIST_SITE',
        hostname: urlObj.hostname
      },
      () => {
        window.location.href = blockedUrl;
      }
    );
  } catch (error) {
    window.location.href = blockedUrl;
  }
});
