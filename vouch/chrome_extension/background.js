// Background service worker: does the actual network calls to the Vouch
// server. Kept out of the content script so requests run in the extension's
// own context rather than the Gmail page's, and the API base is
// configurable from the popup.

const DEFAULT_API_BASE = "http://localhost:8000";

async function getApiBase() {
  const { apiBase } = await chrome.storage.local.get("apiBase");
  return (apiBase || DEFAULT_API_BASE).replace(/\/+$/, "");
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type !== "VOUCH_CHECK_EMAIL") return false;

  (async () => {
    try {
      const apiBase = await getApiBase();

      // The authoritative verdict: sender address (checked against the
      // company's domain + recruiter registry) AND the message body (scanned
      // for scam patterns), combined into one honest verdict server-side.
      const emailResp = await fetch(`${apiBase}/api/verify/email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender_address: msg.senderAddress || null,
          body_text: msg.bodyText || null,
        }),
      });
      const emailData = await emailResp.json().catch(() => null);
      if (!emailResp.ok) {
        sendResponse({ ok: false, error: (emailData && emailData.detail) || `Server error (${emailResp.status})` });
        return;
      }

      // Also run the message text through the scam-pattern scanner on its
      // own. This doesn't change the verdict above (which already folds the
      // same scan in) -- it's purely so the message-content check is shown
      // explicitly, instead of being invisible when it finds nothing.
      let textCheck = null;
      if (msg.bodyText && msg.bodyText.trim()) {
        const textResp = await fetch(`${apiBase}/api/verify/text`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: msg.bodyText }),
        });
        textCheck = await textResp.json().catch(() => null);
      }

      sendResponse({ ok: true, result: emailData, textCheck });
    } catch (e) {
      sendResponse({ ok: false, error: "Couldn't reach Vouch. Is your local server running?" });
    }
  })();

  return true; // keep the message channel open for the async sendResponse above
});
