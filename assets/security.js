(function () {
  var ui = {
    card: null,
    scoreValue: null,
    scoreLevel: null,
    counts: null,
    search: null,
    list: null,
  };

  var current = {
    summary: null,
    findings: [],
  };

  var weights = {
    high: 30,
    medium: 15,
    low: 5,
  };

  function safeText(value) {
    return (value == null ? "" : String(value)).trim();
  }

  function boolAttr(value) {
    var v = safeText(value).toLowerCase();
    if (v === "true") return true;
    if (v === "false") return false;
    return null;
  }

  function parseXml(xmlText) {
    try {
      var parser = new DOMParser();
      var doc = parser.parseFromString(xmlText, "application/xml");
      if (doc.getElementsByTagName("parsererror").length > 0) return null;
      return doc;
    } catch (e) {
      return null;
    }
  }

  function normalizePerm(p) {
    return safeText(p).replace(/\s+/g, "");
  }

  function parsePermissions(text) {
    var lines = safeText(text).split("\n");
    var perms = [];
    for (var i = 0; i < lines.length; i++) {
      var p = normalizePerm(lines[i]);
      if (!p) continue;
      perms.push(p);
    }
    return Array.from(new Set(perms));
  }

  function permBuckets(perms) {
    var HIGH = [
      "android.permission.BIND_ACCESSIBILITY_SERVICE",
      "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.REQUEST_INSTALL_PACKAGES",
      "android.permission.PACKAGE_USAGE_STATS",
      "android.permission.READ_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.SEND_SMS",
      "android.permission.READ_CALL_LOG",
      "android.permission.WRITE_CALL_LOG",
      "android.permission.READ_PHONE_STATE",
      "android.permission.RECORD_AUDIO",
      "android.permission.CAMERA",
      "android.permission.READ_CONTACTS",
      "android.permission.WRITE_CONTACTS",
      "android.permission.GET_ACCOUNTS",
      "android.permission.ACCESS_FINE_LOCATION",
      "android.permission.ACCESS_BACKGROUND_LOCATION",
      "android.permission.MANAGE_EXTERNAL_STORAGE",
    ];

    var MEDIUM = [
      "android.permission.WRITE_SETTINGS",
      "android.permission.RECEIVE_BOOT_COMPLETED",
      "android.permission.FOREGROUND_SERVICE",
      "android.permission.BLUETOOTH_CONNECT",
      "android.permission.BLUETOOTH_SCAN",
      "android.permission.NFC",
      "android.permission.READ_EXTERNAL_STORAGE",
      "android.permission.WRITE_EXTERNAL_STORAGE",
      "android.permission.WAKE_LOCK",
    ];

    var high = [];
    var medium = [];
    for (var i = 0; i < perms.length; i++) {
      var p = perms[i];
      if (HIGH.indexOf(p) !== -1) high.push(p);
      else if (MEDIUM.indexOf(p) !== -1) medium.push(p);
    }
    return { high: high, medium: medium };
  }

  function pushFinding(findings, severity, title, details) {
    findings.push({
      severity: severity,
      title: title,
      details: details,
    });
  }

  function analyzePermissionsFindings(permissionsText) {
    var findings = [];
    var perms = parsePermissions(permissionsText);
    var buckets = permBuckets(perms);

    if (buckets.high.length > 0) {
      pushFinding(
        findings,
        "high",
        "Sensitive permissions requested",
        buckets.high.join(", ")
      );
    }

    if (buckets.medium.length > 0) {
      pushFinding(
        findings,
        "medium",
        "Elevated permissions requested",
        buckets.medium.join(", ")
      );
    }

    return { findings: findings, permissions: perms };
  }

  function getAndroidAttr(el, attrName) {
    return el.getAttribute("android:" + attrName) || el.getAttribute(attrName);
  }

  function hasIntentFilter(el) {
    return el.getElementsByTagName("intent-filter").length > 0;
  }

  function componentName(el) {
    var name = getAndroidAttr(el, "name");
    return safeText(name) || "(unnamed)";
  }

  function scanExportedComponents(doc) {
    var findings = [];
    var components = [
      { tag: "activity", label: "Activity" },
      { tag: "activity-alias", label: "Activity Alias" },
      { tag: "service", label: "Service" },
      { tag: "receiver", label: "Receiver" },
      { tag: "provider", label: "Provider" },
    ];

    var risky = [];
    for (var i = 0; i < components.length; i++) {
      var c = components[i];
      var nodes = doc.getElementsByTagName(c.tag);
      for (var j = 0; j < nodes.length; j++) {
        var el = nodes[j];
        var exported = boolAttr(getAndroidAttr(el, "exported"));
        var effectiveExported = exported === true || (exported == null && hasIntentFilter(el));
        if (!effectiveExported) continue;

        var perm = safeText(getAndroidAttr(el, "permission"));
        if (perm) continue;

        risky.push(c.label + ": " + componentName(el));
      }
    }

    if (risky.length > 0) {
      pushFinding(
        findings,
        "high",
        "Exported components without protection",
        risky.slice(0, 20).join(", ") + (risky.length > 20 ? " …" : "")
      );
    }

    var receiverNodes = doc.getElementsByTagName("receiver");
    var bootReceivers = [];
    for (var r = 0; r < receiverNodes.length; r++) {
      var receiver = receiverNodes[r];
      var actions = receiver.getElementsByTagName("action");
      for (var a = 0; a < actions.length; a++) {
        var actionName = safeText(getAndroidAttr(actions[a], "name"));
        if (actionName === "android.intent.action.BOOT_COMPLETED") {
          bootReceivers.push(componentName(receiver));
          break;
        }
      }
    }

    if (bootReceivers.length > 0) {
      pushFinding(
        findings,
        "medium",
        "Boot receiver declared",
        bootReceivers.slice(0, 20).join(", ") + (bootReceivers.length > 20 ? " …" : "")
      );
    }

    return findings;
  }

  function analyzeManifestFindings(manifestXml) {
    var findings = [];
    var doc = parseXml(manifestXml);
    if (!doc) return findings;

    var apps = doc.getElementsByTagName("application");
    if (apps.length > 0) {
      var app = apps[0];

      var debuggable = boolAttr(getAndroidAttr(app, "debuggable"));
      if (debuggable === true) {
        pushFinding(findings, "high", "Debuggable build enabled", "android:debuggable=\"true\"");
      }

      var cleartext = boolAttr(getAndroidAttr(app, "usesCleartextTraffic"));
      if (cleartext === true) {
        pushFinding(findings, "high", "Cleartext traffic allowed", "android:usesCleartextTraffic=\"true\"");
      }

      var allowBackup = boolAttr(getAndroidAttr(app, "allowBackup"));
      if (allowBackup === true) {
        pushFinding(findings, "medium", "App backups allowed", "android:allowBackup=\"true\"");
      }

      var legacyStorage = boolAttr(getAndroidAttr(app, "requestLegacyExternalStorage"));
      if (legacyStorage === true) {
        pushFinding(
          findings,
          "medium",
          "Legacy external storage requested",
          "android:requestLegacyExternalStorage=\"true\""
        );
      }
    }

    var manifest = doc.getElementsByTagName("manifest");
    if (manifest.length > 0) {
      var sharedUserId = safeText(getAndroidAttr(manifest[0], "sharedUserId"));
      if (sharedUserId) {
        pushFinding(findings, "high", "sharedUserId is set", sharedUserId);
      }
    }

    Array.prototype.push.apply(findings, scanExportedComponents(doc));
    return findings;
  }

  function summarize(findings) {
    var score = 0;
    var counts = { high: 0, medium: 0, low: 0 };
    for (var i = 0; i < findings.length; i++) {
      var s = findings[i].severity;
      if (counts[s] == null) continue;
      counts[s] += 1;
      score += weights[s] || 0;
    }
    if (score > 100) score = 100;

    var level = "Low";
    if (score >= 70 || counts.high >= 2) level = "High";
    else if (score >= 35 || counts.high >= 1 || counts.medium >= 3) level = "Medium";

    return { score: score, level: level, counts: counts };
  }

  function severityRank(s) {
    if (s === "high") return 0;
    if (s === "medium") return 1;
    return 2;
  }

  function analyze(data) {
    var manifestXml = safeText(data && data.manifestXml);
    var permissionsText = safeText(data && data.permissionsText);
    var findings = [];

    if (manifestXml) {
      Array.prototype.push.apply(findings, analyzeManifestFindings(manifestXml));
    }

    if (permissionsText) {
      var permResult = analyzePermissionsFindings(permissionsText);
      Array.prototype.push.apply(findings, permResult.findings);
    }

    findings.sort(function (a, b) {
      var ra = severityRank(a.severity);
      var rb = severityRank(b.severity);
      if (ra !== rb) return ra - rb;
      return a.title.localeCompare(b.title);
    });

    var summary = summarize(findings);
    current.summary = summary;
    current.findings = findings;
    return { summary: summary, findings: findings };
  }

  function ensureUi() {
    if (ui.card) return;
    ui.card = document.getElementById("security-card");
    ui.scoreValue = document.getElementById("security-score-value");
    ui.scoreLevel = document.getElementById("security-score-level");
    ui.counts = document.getElementById("security-counts");
    ui.search = document.getElementById("security-search");
    ui.list = document.getElementById("security-findings");

    if (ui.search) {
      ui.search.addEventListener("input", function () {
        renderList(current.findings, ui.search.value);
      });
    }
  }

  function scoreClass(level) {
    if (level === "High") return "security-pill security-pill--high";
    if (level === "Medium") return "security-pill security-pill--medium";
    return "security-pill security-pill--low";
  }

  function renderList(findings, filter) {
    ensureUi();
    if (!ui.list) return;

    var q = safeText(filter).toLowerCase();
    ui.list.innerHTML = "";

    var shown = 0;
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      var hay = (f.title + " " + f.details).toLowerCase();
      if (q && hay.indexOf(q) === -1) continue;
      shown++;

      var item = document.createElement("div");
      item.className = "security-item security-item--" + f.severity;

      var header = document.createElement("div");
      header.className = "security-item__header";

      var pill = document.createElement("span");
      pill.className = "security-tag security-tag--" + f.severity;
      pill.textContent = f.severity.toUpperCase();

      var title = document.createElement("span");
      title.className = "security-item__title";
      title.textContent = f.title;

      header.appendChild(pill);
      header.appendChild(title);

      var details = document.createElement("div");
      details.className = "security-item__details";
      details.textContent = f.details;

      item.appendChild(header);
      item.appendChild(details);
      ui.list.appendChild(item);
    }

    if (shown === 0) {
      var empty = document.createElement("div");
      empty.className = "security-empty";
      empty.textContent = q ? "No findings match your search." : "No findings yet.";
      ui.list.appendChild(empty);
    }
  }

  function render(result) {
    ensureUi();
    if (!ui.card || !result) return;

    ui.card.style.display = "block";

    if (ui.scoreValue) ui.scoreValue.textContent = String(result.summary.score);
    if (ui.scoreLevel) {
      ui.scoreLevel.textContent = result.summary.level;
      ui.scoreLevel.className = scoreClass(result.summary.level);
    }
    if (ui.counts) {
      ui.counts.textContent =
        result.summary.counts.high +
        " high · " +
        result.summary.counts.medium +
        " medium · " +
        result.summary.counts.low +
        " low";
    }

    renderList(result.findings, ui.search ? ui.search.value : "");
  }

  function reset() {
    ensureUi();
    current.summary = null;
    current.findings = [];
    if (ui.search) ui.search.value = "";
    if (ui.list) ui.list.innerHTML = "";
    if (ui.card) ui.card.style.display = "none";
  }

  window.SecurityScanner = {
    analyze: analyze,
    render: render,
    reset: reset,
    getSummary: function () {
      return current.summary;
    },
  };

  document.addEventListener("DOMContentLoaded", function () {
    ensureUi();
  });
})();
