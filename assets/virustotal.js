(function () {
  var STORAGE_KEY_VIRUSTOTAL_API_KEY = "trustify_virustotal_api_key";
  var API_BASE = "https://www.virustotal.com/api/v3/files/";

  var ui = {};
  var currentHash = "";
  var lastCheckedHash = "";
  var currentResult = null;
  var isChecking = false;

  function $(id) {
    return document.getElementById(id);
  }

  function safeText(value) {
    return (value == null ? "" : String(value)).trim();
  }

  function escapeHtml(value) {
    return safeText(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function getApiKey() {
    if (window.AccountManager && typeof window.AccountManager.getVirusTotalApiKey === "function") {
      return window.AccountManager.getVirusTotalApiKey();
    }
    try {
      return localStorage.getItem(STORAGE_KEY_VIRUSTOTAL_API_KEY) || "";
    } catch (e) {
      return "";
    }
  }

  function ensureUi() {
    ui.card = $("security-card");
    ui.summary = $("virustotal-summary");
    ui.details = $("virustotal-details");
  }

  function showVirusTotalPanel() {
    ensureUi();
    if (ui.card) ui.card.style.display = "block";
  }

  function shortHash(hash) {
    return hash ? hash.slice(0, 12) + "..." + hash.slice(-8) : "";
  }

  function formatDate(seconds) {
    if (!seconds) return "Unknown";
    try {
      return new Date(seconds * 1000).toLocaleString();
    } catch (e) {
      return "Unknown";
    }
  }

  function scoreClass(malicious, suspicious) {
    if (malicious > 0) return "security-pill security-pill--high";
    if (suspicious > 0) return "security-pill security-pill--medium";
    return "security-pill security-pill--low";
  }

  function renderMessage(summary, message, hash) {
    showVirusTotalPanel();
    if (ui.summary) ui.summary.textContent = summary;
    if (!ui.details) return;
    ui.details.innerHTML =
      "<div class='security-empty'>" +
      escapeHtml(message) +
      (hash ? "<div class='virustotal-hash'>SHA-256: " + escapeHtml(shortHash(hash)) + "</div>" : "") +
      "</div>";
  }

  function renderLoading(hash) {
    showVirusTotalPanel();
    if (ui.summary) ui.summary.textContent = "Checking...";
    if (!ui.details) return;
    ui.details.innerHTML =
      "<div class='virustotal-card'>" +
      "<div class='virustotal-card__header'>" +
      "<span class='spinner-sm' aria-hidden='true'></span>" +
      "<div><strong>Checking VirusTotal</strong><span>Looking up the APK SHA-256. The APK file is not uploaded.</span></div>" +
      "</div>" +
      "<div class='virustotal-hash'>SHA-256: " +
      escapeHtml(shortHash(hash)) +
      "</div>" +
      "</div>";
  }

  function topDetections(results) {
    if (!results) return [];
    return Object.keys(results)
      .map(function (engine) {
        var item = results[engine] || {};
        return {
          engine: engine,
          category: item.category || "",
          result: item.result || "",
        };
      })
      .filter(function (item) {
        return item.category === "malicious" || item.category === "suspicious";
      })
      .slice(0, 6);
  }

  function renderReport(hash, data) {
    showVirusTotalPanel();
    var attrs = (data && data.data && data.data.attributes) || {};
    var stats = attrs.last_analysis_stats || {};
    var malicious = stats.malicious || 0;
    var suspicious = stats.suspicious || 0;
    var harmless = stats.harmless || 0;
    var undetected = stats.undetected || 0;
    var total = malicious + suspicious + harmless + undetected + (stats.timeout || 0) + (stats["type-unsupported"] || 0);
    var detections = malicious + suspicious;
    var label =
      attrs.popular_threat_classification && attrs.popular_threat_classification.suggested_threat_label
        ? attrs.popular_threat_classification.suggested_threat_label
        : "";
    var vtUrl = "https://www.virustotal.com/gui/file/" + encodeURIComponent(hash);
    var found = topDetections(attrs.last_analysis_results);

    currentResult = {
      hash: hash,
      detections: detections,
      malicious: malicious,
      suspicious: suspicious,
      total: total,
      lastAnalysisDate: attrs.last_analysis_date || null,
      reputation: attrs.reputation || 0,
      label: label,
      link: vtUrl,
    };

    if (ui.summary) ui.summary.textContent = total ? detections + " / " + total + " flagged" : "Report found";
    if (!ui.details) return;

    ui.details.innerHTML =
      "<div class='virustotal-card'>" +
      "<div class='virustotal-score'>" +
      "<div><span class='security-score__label'>Community detections</span><strong>" +
      escapeHtml(String(detections)) +
      " / " +
      escapeHtml(String(total || "unknown")) +
      "</strong></div>" +
      "<span class='" +
      scoreClass(malicious, suspicious) +
      "'>" +
      (malicious > 0 ? "Detected" : suspicious > 0 ? "Suspicious" : "Clean") +
      "</span>" +
      "</div>" +
      "<div class='virustotal-grid'>" +
      "<div><span>Malicious</span><strong>" +
      malicious +
      "</strong></div>" +
      "<div><span>Suspicious</span><strong>" +
      suspicious +
      "</strong></div>" +
      "<div><span>Harmless</span><strong>" +
      harmless +
      "</strong></div>" +
      "<div><span>Undetected</span><strong>" +
      undetected +
      "</strong></div>" +
      "</div>" +
      "<div class='virustotal-meta'>" +
      "<div><span>Last analysis</span><strong>" +
      escapeHtml(formatDate(attrs.last_analysis_date)) +
      "</strong></div>" +
      "<div><span>Reputation</span><strong>" +
      escapeHtml(String(attrs.reputation || 0)) +
      "</strong></div>" +
      (label ? "<div><span>Threat label</span><strong>" + escapeHtml(label) + "</strong></div>" : "") +
      "<div><span>SHA-256</span><strong>" +
      escapeHtml(shortHash(hash)) +
      "</strong></div>" +
      "</div>" +
      (found.length
        ? "<div class='virustotal-detections'><span>Top detections</span>" +
          found
            .map(function (item) {
              return "<div><strong>" + escapeHtml(item.engine) + "</strong><span>" + escapeHtml(item.result || item.category) + "</span></div>";
            })
            .join("") +
          "</div>"
        : "") +
      "<div class='virustotal-actions'>" +
      "<button id='virustotal-refresh' class='btn-secondary' type='button'>Check again</button>" +
      "<a class='btn-secondary' href='" +
      vtUrl +
      "' target='_blank' rel='noopener'>Open report</a>" +
      "</div>" +
      "</div>";

    var refresh = $("virustotal-refresh");
    if (refresh) {
      refresh.addEventListener("click", function () {
        lookup(hash, true);
      });
    }
  }

  function renderError(hash, message) {
    showVirusTotalPanel();
    if (ui.summary) ui.summary.textContent = "Unavailable";
    if (!ui.details) return;
    ui.details.innerHTML =
      "<div class='security-empty'>" +
      escapeHtml(message) +
      (hash ? "<div class='virustotal-hash'>SHA-256: " + escapeHtml(shortHash(hash)) + "</div>" : "") +
      "</div>";
  }

  async function lookup(hash, force) {
    hash = safeText(hash).toLowerCase();
    if (!hash) {
      renderMessage("Waiting", "Waiting for the APK SHA-256 hash.");
      return;
    }

    currentHash = hash;
    var key = getApiKey();
    if (!key) {
      renderMessage("API key needed", "Add a VirusTotal API key in Account & History to check this APK hash.", hash);
      return;
    }

    if (isChecking && !force) return;
    isChecking = true;
    lastCheckedHash = hash;
    renderLoading(hash);

    try {
      var response = await fetch(API_BASE + encodeURIComponent(hash), {
        method: "GET",
        headers: { "x-apikey": key },
      });
      var data = await response.json().catch(function () {
        return null;
      });

      if (response.status === 404) {
        renderError(hash, "VirusTotal has no existing report for this APK hash.");
        return;
      }

      if (!response.ok) {
        var apiMessage =
          data && data.error && data.error.message
            ? data.error.message
            : "VirusTotal lookup failed with status " + response.status + ".";
        renderError(hash, apiMessage);
        return;
      }

      renderReport(hash, data);
    } catch (e) {
      renderError(hash, "Could not reach VirusTotal from this browser. Check network access, CORS, or the API key.");
    } finally {
      isChecking = false;
    }
  }

  function checkCurrentSignature(force) {
    if (!window.SecurityScanner || typeof window.SecurityScanner.getSignature !== "function") return;
    var signature = window.SecurityScanner.getSignature();
    var hash = signature && signature.apkSha256 ? signature.apkSha256 : "";
    if (!hash) {
      renderMessage("Waiting", "Waiting for the APK SHA-256 hash.");
      return;
    }
    if (!force && hash === currentHash && (currentResult || lastCheckedHash === hash)) return;
    lookup(hash, force);
  }

  function reset() {
    currentHash = "";
    lastCheckedHash = "";
    currentResult = null;
    isChecking = false;
    ensureUi();
    if (ui.card) ui.card.style.display = "none";
    if (ui.summary) ui.summary.textContent = "Not checked";
    if (ui.details) {
      ui.details.innerHTML = "<div class='security-empty'>Add a VirusTotal API key in Account &amp; History to check this APK hash.</div>";
    }
  }

  function patchSecurityScanner() {
    if (!window.SecurityScanner || window.SecurityScanner.__virusTotalPatched) return;
    var originalRender = window.SecurityScanner.render;
    var originalReset = window.SecurityScanner.reset;
    var originalComputeSignature = window.SecurityScanner.computeSignature;

    window.SecurityScanner.render = function () {
      var value = originalRender.apply(window.SecurityScanner, arguments);
      setTimeout(function () {
        checkCurrentSignature(false);
      }, 0);
      return value;
    };

    window.SecurityScanner.reset = function () {
      var value = originalReset.apply(window.SecurityScanner, arguments);
      reset();
      return value;
    };

    if (typeof originalComputeSignature === "function") {
      window.SecurityScanner.computeSignature = function () {
        var signaturePromise = originalComputeSignature.apply(window.SecurityScanner, arguments);
        if (signaturePromise && typeof signaturePromise.then === "function") {
          signaturePromise.then(function (signature) {
            var hash = signature && signature.apkSha256 ? signature.apkSha256 : "";
            if (hash) lookup(hash, false);
          }).catch(function () {});
        }
        return signaturePromise;
      };
    }

    window.SecurityScanner.__virusTotalPatched = true;
  }

  window.VirusTotalLookup = {
    lookup: lookup,
    refresh: function () {
      checkCurrentSignature(true);
    },
    getResult: function () {
      return currentResult;
    },
  };

  document.addEventListener("DOMContentLoaded", function () {
    ensureUi();
    patchSecurityScanner();
    reset();
  });

  window.addEventListener("trustify:virustotal-key-updated", function () {
    checkCurrentSignature(true);
  });
})();
