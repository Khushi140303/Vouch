/**
 * Vouch trust badge — drop this on any careers page with:
 *
 *   <div id="vouch-badge" data-company-id="1" data-api-base="http://localhost:8000"></div>
 *   <script src="badge.js"></script>
 *
 * It fetches the company's public trust-file live from Vouch and renders
 * a small verified chip. Fails silently (logs to console, hides itself)
 * if the company isn't verified yet or the API is unreachable -- a
 * broken badge should never look like a broken page.
 */
(function () {
  function init() {
    var el = document.getElementById("vouch-badge");
    if (!el) return;

    var companyId = el.getAttribute("data-company-id") || "1";
    var apiBase = el.getAttribute("data-api-base") || "http://localhost:8000";

    el.innerHTML =
      '<span class="vouch-badge vouch-badge--loading">Checking employer verification…</span>';

    fetch(apiBase + "/api/company/" + companyId + "/trust-file")
      .then(function (r) {
        if (!r.ok) throw new Error("not verified");
        return r.json();
      })
      .then(function (data) {
        var domain = data.official_domains[0];
        var recruiterCount = data.recruiters.length;
        var verifyUrl = data.verify_url || apiBase + "/verify";

        el.innerHTML =
          '<a class="vouch-badge vouch-badge--verified" ' +
          'href="' + verifyUrl + '?company=' + encodeURIComponent(domain) + '" ' +
          'target="_blank" rel="noopener">' +
            '<span class="vouch-badge__check">&#10003;</span>' +
            '<span class="vouch-badge__text">' +
              '<strong>' + escapeHtml(data.company) + '</strong> is verified on Vouch' +
              (recruiterCount ? ' &middot; ' + recruiterCount + ' registered recruiter' +
                (recruiterCount === 1 ? "" : "s") : '') +
            '</span>' +
            '<span class="vouch-badge__cta">Check any offer you receive &rarr;</span>' +
          '</a>';
      })
      .catch(function (err) {
        console.warn("[vouch-badge] could not load trust file:", err);
        el.style.display = "none";
      });
  }

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // inject minimal styling once, scoped to the badge classes only
  if (!document.getElementById("vouch-badge-styles")) {
    var style = document.createElement("style");
    style.id = "vouch-badge-styles";
    style.textContent =
      '.vouch-badge{display:inline-flex;align-items:center;gap:10px;' +
      'font:14px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;' +
      'padding:10px 16px;border-radius:10px;text-decoration:none;' +
      'transition:box-shadow .15s ease;}' +
      '.vouch-badge--loading{color:#8a8f98;background:#f4f5f7;}' +
      '.vouch-badge--verified{color:#0a7d33;background:#eafaf0;' +
      'border:1px solid #b8ecc9;}' +
      '.vouch-badge--verified:hover{box-shadow:0 2px 8px rgba(10,125,51,0.15);}' +
      '.vouch-badge__check{display:inline-flex;align-items:center;justify-content:center;' +
      'width:20px;height:20px;border-radius:50%;background:#0a7d33;color:#fff;' +
      'font-size:12px;flex-shrink:0;}' +
      '.vouch-badge__text{color:#1a3d24;}' +
      '.vouch-badge__cta{color:#0a7d33;font-weight:600;white-space:nowrap;}';
    document.head.appendChild(style);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
