// Content script: runs inside the Gmail tab, reads the open message, and
// asks the background worker to check it with Vouch -- both the sender
// address (against the recruiter registry) and the message body (against
// the scam-pattern rules).
//
// IMPORTANT CAVEAT (say this out loud in the demo): this reads Gmail's
// rendered page, not the Gmail API. That means it can check the sender
// address, the company's recruiter registry, and the message text for scam
// patterns -- but it can NOT see SPF/DKIM/DMARC results, because those only
// exist in the raw message source ("Show original"), which the normal inbox
// view never renders. A production build would use the official Gmail API
// (OAuth) to pull the raw source and get the full check, same as the
// Email-tab "paste full source" flow already does.
//
// Gmail's own CSS class names below (span.gD, h2.hP, div.a3s) are unofficial
// and undocumented -- they're what the rendered inbox actually uses today,
// but Google can rename them at any time. If the badge stops appearing,
// that's the first thing to check.

(function () {
  const CARD_ID = "vouch-check-card";
  let lastMessageKey = null;
  let debounceTimer = null;

  function getOpenMessageEls() {
    const senderEl = document.querySelector("span.gD");
    const subjectEl = document.querySelector("h2.hP");
    const bodyEl = document.querySelector("div.a3s.aiL") || document.querySelector("div.a3s");
    return { senderEl, subjectEl, bodyEl };
  }

  function extractData() {
    const { senderEl, subjectEl, bodyEl } = getOpenMessageEls();
    if (!senderEl) return null;
    const senderAddress = senderEl.getAttribute("email") || "";
    if (!senderAddress) return null;
    const subject = subjectEl ? subjectEl.textContent.trim() : "";
    const bodyText = bodyEl ? bodyEl.innerText.trim() : "";
    return { senderAddress, subject, bodyText };
  }

  function messageKey(data) {
    return `${data.senderAddress}::${data.subject}::${data.bodyText.length}`;
  }

  function removeCard() {
    const existing = document.getElementById(CARD_ID);
    if (existing) existing.remove();
  }

  function escapeHtml(s) {
    return (s || "").replace(/[&<>"']/g, (c) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
    ));
  }

  function renderLoading(anchor) {
    removeCard();
    const card = document.createElement("div");
    card.id = CARD_ID;
    card.className = "vouch-card vouch-loading";
    card.innerHTML = '<span class="vouch-dot"></span> Checking sender and message with Vouch…';
    anchor.insertAdjacentElement("beforebegin", card);
  }

  function verdictMeta(verdict) {
    if (verdict === "verified") return { cls: "vouch-verified", icon: "✓", label: "Verified" };
    if (verdict === "scam") return { cls: "vouch-scam", icon: "⚠", label: "Likely Scam" };
    return { cls: "vouch-unverifiable", icon: "?", label: "Can't Verify" };
  }

  function renderMessageCheckSection(textCheck) {
    if (!textCheck) return "";
    const flags = textCheck.flags || [];
    if (flags.length === 0) {
      return `
        <div class="vouch-subsection">
          <div class="vouch-subhead">Message content</div>
          <p class="vouch-subtext">No scam patterns found in the message text.</p>
        </div>
      `;
    }
    const items = flags.map((f) => `<li>${escapeHtml(f.label)}</li>`).join("");
    return `
      <div class="vouch-subsection">
        <div class="vouch-subhead">Message content — ${flags.length} pattern(s) found</div>
        <ul class="vouch-reasons">${items}</ul>
      </div>
    `;
  }

  function renderResult(anchor, payload) {
    removeCard();
    const card = document.createElement("div");
    card.id = CARD_ID;

    if (!payload || !payload.ok) {
      card.className = "vouch-card vouch-error";
      card.innerHTML = `<b>Vouch:</b> ${escapeHtml((payload && payload.error) || "Something went wrong.")}`;
      anchor.insertAdjacentElement("beforebegin", card);
      return;
    }

    const { verdict, reasons } = payload.result;
    const { cls, icon, label } = verdictMeta(verdict);
    const reasonsHtml = (reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
    card.className = `vouch-card ${cls}`;
    card.innerHTML = `
      <div class="vouch-header">
        <span class="vouch-icon">${icon}</span>
        <span class="vouch-label">${label}</span>
        <span class="vouch-brand">Vouch</span>
      </div>
      <div class="vouch-subsection">
        <div class="vouch-subhead">Sender &amp; recruiter registry</div>
        <ul class="vouch-reasons">${reasonsHtml}</ul>
      </div>
      ${renderMessageCheckSection(payload.textCheck)}
    `;
    anchor.insertAdjacentElement("beforebegin", card);
  }

  function checkCurrentMessage() {
    const data = extractData();
    if (!data) {
      removeCard();
      lastMessageKey = null;
      return;
    }
    const key = messageKey(data);
    if (key === lastMessageKey) return;
    lastMessageKey = key;

    const { bodyEl, senderEl } = getOpenMessageEls();
    const anchor = bodyEl || senderEl;
    if (!anchor) return;

    renderLoading(anchor);
    chrome.runtime.sendMessage(
      {
        type: "VOUCH_CHECK_EMAIL",
        senderAddress: data.senderAddress,
        bodyText: `${data.subject}\n\n${data.bodyText}`,
      },
      (response) => {
        if (!document.body.contains(anchor)) return; // the view moved on while we waited
        renderResult(anchor, response);
      }
    );
  }

  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(checkCurrentMessage, 600);
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // Gmail may already have a message open when the extension loads/reloads.
  setTimeout(checkCurrentMessage, 1500);
})();
