(function () {
  var ui = {
    card: null,
    scoreValue: null,
    scoreLevel: null,
    counts: null,
    downloadReport: null,
    downloadPdf: null,
    search: null,
    list: null,
    signatureSummary: null,
    signatureDetails: null,
    exportedSearch: null,
    exportedCount: null,
    exportedList: null,
  };

  var current = {
    summary: null,
    findings: [],
    exportedComponents: [],
    meta: null,
    signature: null,
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

  function getIntentSummary(el) {
    var filters = el.getElementsByTagName("intent-filter");
    var actions = [];
    var categories = [];
    var dataItems = [];
    for (var i = 0; i < filters.length; i++) {
      var f = filters[i];
      var aNodes = f.getElementsByTagName("action");
      for (var a = 0; a < aNodes.length; a++) {
        var actionName = safeText(getAndroidAttr(aNodes[a], "name"));
        if (actionName) actions.push(actionName);
      }
      var cNodes = f.getElementsByTagName("category");
      for (var c = 0; c < cNodes.length; c++) {
        var catName = safeText(getAndroidAttr(cNodes[c], "name"));
        if (catName) categories.push(catName);
      }
      var dNodes = f.getElementsByTagName("data");
      for (var d = 0; d < dNodes.length; d++) {
        var scheme = safeText(getAndroidAttr(dNodes[d], "scheme"));
        var host = safeText(getAndroidAttr(dNodes[d], "host"));
        var path = safeText(getAndroidAttr(dNodes[d], "path"));
        var prefix = safeText(getAndroidAttr(dNodes[d], "pathPrefix"));
        var mime = safeText(getAndroidAttr(dNodes[d], "mimeType"));
        var parts = [];
        if (scheme) parts.push("scheme=" + scheme);
        if (host) parts.push("host=" + host);
        if (path) parts.push("path=" + path);
        if (prefix) parts.push("pathPrefix=" + prefix);
        if (mime) parts.push("mimeType=" + mime);
        if (parts.length > 0) dataItems.push(parts.join(", "));
      }
    }

    actions = Array.from(new Set(actions));
    categories = Array.from(new Set(categories));
    dataItems = Array.from(new Set(dataItems));

    return { actions: actions, categories: categories, data: dataItems };
  }

  function componentName(el) {
    var name = getAndroidAttr(el, "name");
    return safeText(name) || "(unnamed)";
  }

  function collectExportedComponents(doc) {
    var components = [
      { tag: "activity", label: "Activity" },
      { tag: "activity-alias", label: "Activity Alias" },
      { tag: "service", label: "Service" },
      { tag: "receiver", label: "Receiver" },
      { tag: "provider", label: "Provider" },
    ];

    var exportedComponents = [];
    for (var i = 0; i < components.length; i++) {
      var c = components[i];
      var nodes = doc.getElementsByTagName(c.tag);
      for (var j = 0; j < nodes.length; j++) {
        var el = nodes[j];
        var exportedAttr = boolAttr(getAndroidAttr(el, "exported"));
        var implicitExported = exportedAttr == null && hasIntentFilter(el);
        var effectiveExported = exportedAttr === true || implicitExported;
        if (!effectiveExported) continue;

        var permission = safeText(getAndroidAttr(el, "permission"));
        var readPermission = safeText(getAndroidAttr(el, "readPermission"));
        var writePermission = safeText(getAndroidAttr(el, "writePermission"));
        var authorities = safeText(getAndroidAttr(el, "authorities"));
        var grantUriPermissions = boolAttr(getAndroidAttr(el, "grantUriPermissions"));
        var intents = getIntentSummary(el);

        var hasProtection =
          !!permission || !!readPermission || !!writePermission;

        var severity = hasProtection ? "low" : "high";

        var evidenceParts = [];
        evidenceParts.push(
          exportedAttr == null
            ? "android:exported=implicit"
            : "android:exported=" + (exportedAttr ? "true" : "false")
        );
        if (permission) evidenceParts.push("permission=" + permission);
        if (readPermission) evidenceParts.push("readPermission=" + readPermission);
        if (writePermission) evidenceParts.push("writePermission=" + writePermission);
        if (authorities) evidenceParts.push("authorities=" + authorities);
        if (grantUriPermissions === true) evidenceParts.push("grantUriPermissions=true");
        if (intents.actions.length > 0) evidenceParts.push("actions=" + intents.actions.join(", "));

        exportedComponents.push({
          type: c.label,
          tag: c.tag,
          name: componentName(el),
          exported: true,
          exportedMode: exportedAttr == null ? "Implicit" : "Explicit",
          permission: permission,
          readPermission: readPermission,
          writePermission: writePermission,
          authorities: authorities,
          grantUriPermissions: grantUriPermissions === true,
          intentActions: intents.actions,
          intentCategories: intents.categories,
          intentData: intents.data,
          protected: hasProtection,
          severity: severity,
          evidence: evidenceParts.join(" · "),
        });
      }
    }

    exportedComponents.sort(function (a, b) {
      if (a.severity !== b.severity) return severityRank(a.severity) - severityRank(b.severity);
      if (a.type !== b.type) return a.type.localeCompare(b.type);
      return a.name.localeCompare(b.name);
    });

    return exportedComponents;
  }

  function analyzeExportedFindings(doc, exportedComponents) {
    var findings = [];
    var risky = [];
    for (var i = 0; i < exportedComponents.length; i++) {
      var c = exportedComponents[i];
      if (c.protected) continue;
      risky.push(c.type + ": " + c.name);
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

  function analyzeManifest(manifestXml) {
    var findings = [];
    var doc = parseXml(manifestXml);
    if (!doc) return { findings: findings, exportedComponents: [] };

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

    var exportedComponents = collectExportedComponents(doc);
    Array.prototype.push.apply(findings, analyzeExportedFindings(doc, exportedComponents));
    return { findings: findings, exportedComponents: exportedComponents };
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
    var meta = (data && data.meta) || null;
    var signature = (data && data.signature) || null;
    var findings = [];
    var exportedComponents = [];

    if (manifestXml) {
      var manifestResult = analyzeManifest(manifestXml);
      Array.prototype.push.apply(findings, manifestResult.findings);
      exportedComponents = manifestResult.exportedComponents;
    }

    if (permissionsText) {
      var permResult = analyzePermissionsFindings(permissionsText);
      Array.prototype.push.apply(findings, permResult.findings);
    }

    if (signature) {
      Array.prototype.push.apply(findings, analyzeSignatureFindings(signature));
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
    current.exportedComponents = exportedComponents;
    current.meta = meta;
    current.signature = signature;
    return { summary: summary, findings: findings, exportedComponents: exportedComponents };
  }

  function ensureUi() {
    if (ui.card) return;
    ui.card = document.getElementById("security-card");
    ui.scoreValue = document.getElementById("security-score-value");
    ui.scoreLevel = document.getElementById("security-score-level");
    ui.counts = document.getElementById("security-counts");
    ui.downloadReport = document.getElementById("download-security-report");
    ui.downloadPdf = document.getElementById("download-security-pdf");
    ui.search = document.getElementById("security-search");
    ui.list = document.getElementById("security-findings");
    ui.signatureSummary = document.getElementById("signature-summary");
    ui.signatureDetails = document.getElementById("signature-details");
    ui.exportedSearch = document.getElementById("exported-search");
    ui.exportedCount = document.getElementById("exported-count");
    ui.exportedList = document.getElementById("exported-components");

    if (ui.search) {
      ui.search.addEventListener("input", function () {
        renderList(current.findings, ui.search.value);
      });
    }

    if (ui.downloadReport) {
      ui.downloadReport.addEventListener("click", function () {
        downloadCurrentReport();
      });
    }

    if (ui.downloadPdf) {
      ui.downloadPdf.addEventListener("click", function () {
        downloadCurrentPdf();
      });
    }

    if (ui.exportedSearch) {
      ui.exportedSearch.addEventListener("input", function () {
        renderExported(current.exportedComponents, ui.exportedSearch.value);
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

  function analyzeSignatureFindings(signature) {
    var findings = [];
    if (!signature) return findings;

    var v1 = !!(signature.schemes && signature.schemes.v1);
    var v2 = !!(signature.schemes && signature.schemes.v2);
    var v3 = !!(signature.schemes && signature.schemes.v3);

    if (!v1 && !v2 && !v3) {
      pushFinding(findings, "high", "No APK signature detected", "No v1/v2/v3 signature evidence found.");
      return findings;
    }

    if (v1 && !v2 && !v3) {
      pushFinding(
        findings,
        "medium",
        "Only v1 (JAR) signature detected",
        "Modern Android expects v2/v3 for stronger tamper protection."
      );
    }

    if (signature.primaryCert) {
      var cert = signature.primaryCert;
      if (cert.notAfter) {
        var now = Date.now();
        var exp = Date.parse(cert.notAfter);
        if (!isNaN(exp) && exp < now) {
          pushFinding(
            findings,
            "high",
            "Signing certificate expired",
            "notAfter=" + cert.notAfter
          );
        }
      }

      var subj = safeText(cert.subject);
      if (subj.toLowerCase().indexOf("android debug") !== -1) {
        pushFinding(
          findings,
          "high",
          "Debug signing certificate detected",
          "Subject looks like a debug keystore: " + cert.subject
        );
      }
    }

    return findings;
  }

  function renderSignature(signature) {
    ensureUi();
    if (!ui.signatureSummary || !ui.signatureDetails) return;

    ui.signatureDetails.innerHTML = "";

    if (!signature) {
      ui.signatureSummary.textContent = "Not available";
      addSignatureRow("Status", "Waiting for signature scan…");
      if (ui.downloadReport) ui.downloadReport.disabled = !current.summary;
      if (ui.downloadPdf) ui.downloadPdf.disabled = !current.summary;
      return;
    }

    var parts = [];
    if (signature.schemes) {
      if (signature.schemes.v1) parts.push("v1");
      if (signature.schemes.v2) parts.push("v2");
      if (signature.schemes.v3) parts.push("v3");
    }
    ui.signatureSummary.textContent = parts.length > 0 ? parts.join(" + ") : "Unknown";

    if (signature.apkSha256) addSignatureRow("APK SHA-256", signature.apkSha256);
    if (signature.primaryCert && signature.primaryCert.fingerprintSha256) {
      addSignatureRow("Cert SHA-256", signature.primaryCert.fingerprintSha256);
    }
    if (signature.primaryCert && signature.primaryCert.subject) {
      addSignatureRow("Subject", signature.primaryCert.subject);
    }
    if (signature.primaryCert && signature.primaryCert.issuer) {
      addSignatureRow("Issuer", signature.primaryCert.issuer);
    }
    if (signature.primaryCert && signature.primaryCert.notBefore) {
      addSignatureRow("Valid from", signature.primaryCert.notBefore);
    }
    if (signature.primaryCert && signature.primaryCert.notAfter) {
      addSignatureRow("Valid to", signature.primaryCert.notAfter);
    }

    if (!signature.primaryCert) {
      addSignatureRow("Certificate", signature.certError || "Certificate details unavailable");
    }

    if (ui.downloadReport) ui.downloadReport.disabled = !current.summary;
    if (ui.downloadPdf) ui.downloadPdf.disabled = !current.summary;
  }

  function addSignatureRow(label, value) {
    if (!ui.signatureDetails) return;
    var row = document.createElement("div");
    row.className = "signature-row";
    var l = document.createElement("div");
    l.className = "signature-row__label";
    l.textContent = label;
    var v = document.createElement("div");
    v.className = "signature-row__value";
    v.textContent = safeText(value);
    row.appendChild(l);
    row.appendChild(v);
    ui.signatureDetails.appendChild(row);
  }

  function buildReportObject() {
    var now = new Date();
    return {
      generatedAt: now.toISOString(),
      app: current.meta || null,
      signature: current.signature || null,
      security: {
        summary: current.summary || null,
        findings: current.findings || [],
        exportedComponents: current.exportedComponents || [],
      },
      virusTotal:
        window.VirusTotalLookup && typeof window.VirusTotalLookup.getResult === "function"
          ? window.VirusTotalLookup.getResult()
          : null,
    };
  }

  function downloadCurrentReport() {
    try {
      var report = buildReportObject();
      if (!report.security || !report.security.summary) return;

      var pkg = (report.app && report.app.packageName) || "apk";
      var stamp = new Date().toISOString().replace(/[:.]/g, "-");
      var filename = "trustify-security-report-" + pkg + "-" + stamp + ".json";
      var json = JSON.stringify(report, null, 2);
      var blob = new Blob([json], { type: "application/json" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () {
        URL.revokeObjectURL(url);
      }, 5000);
    } catch (e) {}
  }

  function escapeHtml(s) {
    return safeText(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function reportTitle(report) {
    var pkg = (report.app && report.app.packageName) || "apk";
    return "Trustify Security Report - " + pkg;
  }

  function printReportDocument(report, doc, printTarget, cleanup) {
    if (!doc || !printTarget) return false;
    doc.open();
    doc.write(buildPrintableHtml(report));
    doc.close();
    printTarget.setTimeout(function () {
      try {
        printTarget.focus();
        printTarget.print();
      } catch (e) {
      } finally {
        if (cleanup) {
          printTarget.setTimeout(cleanup, 1000);
        }
      }
    }, 350);
    return true;
  }

  function buildPrintableHtml(report) {
    var summary = (report.security && report.security.summary) || null;
    var findings = (report.security && report.security.findings) || [];
    var exported = (report.security && report.security.exportedComponents) || [];
    var sig = report.signature || null;

    var pkg = (report.app && report.app.packageName) || "";
    var label = (report.app && report.app.appLabel) || "";
    var minSdk = (report.app && report.app.minSdk) || "";
    var targetSdk = (report.app && report.app.targetSdk) || "";
    var fileName = (report.app && report.app.fileName) || "";
    var fileSize = (report.app && report.app.fileSize) || 0;

    var schemes = [];
    if (sig && sig.schemes) {
      if (sig.schemes.v1) schemes.push("v1");
      if (sig.schemes.v2) schemes.push("v2");
      if (sig.schemes.v3) schemes.push("v3");
    }

    var html = "";
    html += "<!doctype html><html><head><meta charset='utf-8'/>";
    html += "<meta name='viewport' content='width=device-width, initial-scale=1'/>";
    html += "<title>" + escapeHtml(reportTitle(report)) + "</title>";
    html += "<style>";
    html += "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b0b0f;color:#f3f4f6}";
    html += ".page{max-width:980px;margin:0 auto;padding:32px}";
    html += "h1{font-size:22px;margin:0 0 8px} .muted{color:#a1a1aa}";
    html += ".grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px}";
    html += ".card{border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.04);border-radius:14px;padding:14px}";
    html += ".row{display:flex;justify-content:space-between;gap:12px;margin:6px 0}";
    html += ".k{color:#a1a1aa;font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:700}";
    html += ".v{font-size:13px;word-break:break-word;text-align:right}";
    html += ".pill{display:inline-block;border:1px solid rgba(255,255,255,.16);padding:3px 10px;border-radius:999px;font-size:12px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}";
    html += ".pill.low{background:rgba(16,185,129,.14);border-color:rgba(16,185,129,.3)}";
    html += ".pill.medium{background:rgba(245,158,11,.16);border-color:rgba(245,158,11,.32)}";
    html += ".pill.high{background:rgba(239,68,68,.16);border-color:rgba(239,68,68,.34)}";
    html += "table{width:100%;border-collapse:collapse;margin-top:10px}";
    html += "th,td{border-bottom:1px solid rgba(255,255,255,.10);padding:10px 8px;text-align:left;vertical-align:top}";
    html += "th{color:#a1a1aa;font-size:12px;text-transform:uppercase;letter-spacing:.06em}";
    html += ".sev{font-weight:800;text-transform:uppercase;font-size:12px}";
    html += ".sev.high{color:#fecaca} .sev.medium{color:#fde68a} .sev.low{color:#bbf7d0}";
    html += "@media print{body{background:#fff;color:#111} .muted{color:#444} .card{background:#fff;border-color:#ddd} th,td{border-bottom:1px solid #ddd} .k{color:#444}}";
    html += "@page{margin:14mm}";
    html += "</style></head><body><div class='page'>";

    html += "<h1>" + escapeHtml(reportTitle(report)) + "</h1>";
    html += "<div class='muted'>Generated: " + escapeHtml(report.generatedAt || "") + "</div>";

    if (summary) {
      var lvl = safeText(summary.level).toLowerCase();
      html += "<div style='margin-top:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap'>";
      html += "<span class='pill " + escapeHtml(lvl) + "'>" + escapeHtml(summary.level) + " - " + escapeHtml(summary.score) + "</span>";
      html += "<span class='muted'>" + escapeHtml(summary.counts.high + " high - " + summary.counts.medium + " medium - " + summary.counts.low + " low") + "</span>";
      html += "</div>";
    }

    html += "<div class='grid'>";
    html += "<div class='card'><div class='k'>App</div>";
    html += "<div class='row'><div class='k'>Name</div><div class='v'>" + escapeHtml(label) + "</div></div>";
    html += "<div class='row'><div class='k'>Package</div><div class='v'>" + escapeHtml(pkg) + "</div></div>";
    html += "<div class='row'><div class='k'>minSdk</div><div class='v'>" + escapeHtml(minSdk) + "</div></div>";
    html += "<div class='row'><div class='k'>targetSdk</div><div class='v'>" + escapeHtml(targetSdk) + "</div></div>";
    html += "<div class='row'><div class='k'>File</div><div class='v'>" + escapeHtml(fileName) + "</div></div>";
    html += "<div class='row'><div class='k'>Size</div><div class='v'>" + escapeHtml(String(fileSize)) + "</div></div>";
    html += "</div>";

    html += "<div class='card'><div class='k'>Signature</div>";
    html += "<div class='row'><div class='k'>Schemes</div><div class='v'>" + escapeHtml(schemes.length ? schemes.join(" + ") : "Unknown") + "</div></div>";
    html += "<div class='row'><div class='k'>APK SHA-256</div><div class='v'>" + escapeHtml(sig && sig.apkSha256 ? sig.apkSha256 : "") + "</div></div>";
    if (sig && sig.primaryCert) {
      html += "<div class='row'><div class='k'>Cert SHA-256</div><div class='v'>" + escapeHtml(sig.primaryCert.fingerprintSha256 || "") + "</div></div>";
      html += "<div class='row'><div class='k'>Subject</div><div class='v'>" + escapeHtml(sig.primaryCert.subject || "") + "</div></div>";
      html += "<div class='row'><div class='k'>Issuer</div><div class='v'>" + escapeHtml(sig.primaryCert.issuer || "") + "</div></div>";
      html += "<div class='row'><div class='k'>Valid</div><div class='v'>" + escapeHtml((sig.primaryCert.notBefore || "") + " to " + (sig.primaryCert.notAfter || "")) + "</div></div>";
    } else {
      html += "<div class='muted' style='margin-top:8px'>Certificate details unavailable" + (sig && sig.certError ? ": " + escapeHtml(sig.certError) : ".") + "</div>";
    }
    html += "</div></div>";

    html += "<div class='card' style='margin-top:14px'><div class='k'>Findings</div>";
    html += "<table><thead><tr><th>Severity</th><th>Title</th><th>Details</th></tr></thead><tbody>";
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      var sev = safeText(f.severity).toLowerCase();
      html += "<tr>";
      html += "<td class='sev " + escapeHtml(sev) + "'>" + escapeHtml(f.severity) + "</td>";
      html += "<td>" + escapeHtml(f.title) + "</td>";
      html += "<td class='muted'>" + escapeHtml(f.details) + "</td>";
      html += "</tr>";
    }
    if (findings.length === 0) {
      html += "<tr><td colspan='3' class='muted'>No findings.</td></tr>";
    }
    html += "</tbody></table></div>";

    html += "<div class='card' style='margin-top:14px'><div class='k'>Exported Components</div>";
    html += "<table><thead><tr><th>Status</th><th>Component</th><th>Evidence</th></tr></thead><tbody>";
    for (var e = 0; e < exported.length; e++) {
      var c = exported[e];
      var status = c.protected ? "PROTECTED" : "UNPROTECTED";
      html += "<tr>";
      html += "<td class='sev " + (c.protected ? "low" : "high") + "'>" + escapeHtml(status) + "</td>";
      html += "<td>" + escapeHtml(c.type + ": " + c.name) + "</td>";
      html += "<td class='muted'>" + escapeHtml(c.evidence) + "</td>";
      html += "</tr>";
    }
    if (exported.length === 0) {
      html += "<tr><td colspan='3' class='muted'>No exported components detected.</td></tr>";
    }
    html += "</tbody></table></div>";

    html += "<div class='muted' style='margin-top:14px;font-size:12px'>Tip: In the print dialog, choose Save as PDF.</div>";
    html += "</div></body></html>";
    return html;
  }

  function downloadCurrentPdf() {
    try {
      var report = buildReportObject();
      if (!report.security || !report.security.summary) return;

      var w = window.open("", "_blank");
      if (w && printReportDocument(report, w.document, w)) return;

      var frame = document.createElement("iframe");
      frame.style.position = "fixed";
      frame.style.right = "0";
      frame.style.bottom = "0";
      frame.style.width = "0";
      frame.style.height = "0";
      frame.style.border = "0";
      frame.setAttribute("aria-hidden", "true");
      document.body.appendChild(frame);

      var cleanup = function () {
        if (frame && frame.parentNode) frame.parentNode.removeChild(frame);
      };
      var frameWindow = frame.contentWindow || frame;
      if (!printReportDocument(report, frameWindow.document, frameWindow, cleanup)) cleanup();
    } catch (e) {}
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

    renderSignature(current.signature);
    renderList(result.findings, ui.search ? ui.search.value : "");
    renderExported(
      result.exportedComponents || [],
      ui.exportedSearch ? ui.exportedSearch.value : ""
    );
  }

  function renderExported(exportedComponents, filter) {
    ensureUi();
    if (!ui.exportedList) return;

    var q = safeText(filter).toLowerCase();
    ui.exportedList.innerHTML = "";

    if (ui.exportedCount) {
      ui.exportedCount.textContent = String(exportedComponents.length) + " total";
    }

    var shown = 0;
    for (var i = 0; i < exportedComponents.length; i++) {
      var c = exportedComponents[i];
      var hay =
        (c.type +
          " " +
          c.name +
          " " +
          c.evidence +
          " " +
          c.permission +
          " " +
          c.readPermission +
          " " +
          c.writePermission).toLowerCase();
      if (q && hay.indexOf(q) === -1) continue;
      shown++;

      var item = document.createElement("div");
      item.className = "exported-item exported-item--" + c.severity;

      var header = document.createElement("div");
      header.className = "exported-item__header";

      var tag = document.createElement("span");
      tag.className = "security-tag security-tag--" + (c.protected ? "low" : "high");
      tag.textContent = c.protected ? "PROTECTED" : "UNPROTECTED";

      var mode = document.createElement("span");
      mode.className = "security-tag";
      mode.textContent = c.exportedMode.toUpperCase();

      var title = document.createElement("span");
      title.className = "exported-item__title";
      title.textContent = c.type + ": " + c.name;

      header.appendChild(tag);
      header.appendChild(mode);
      header.appendChild(title);

      var details = document.createElement("div");
      details.className = "exported-item__details";
      details.textContent = c.evidence;

      item.appendChild(header);
      item.appendChild(details);
      ui.exportedList.appendChild(item);
    }

    if (shown === 0) {
      var empty = document.createElement("div");
      empty.className = "security-empty";
      empty.textContent = q
        ? "No exported components match your search."
        : "No exported components detected.";
      ui.exportedList.appendChild(empty);
    }
  }

  function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      if (h.length === 1) h = "0" + h;
      hex.push(h);
    }
    return hex.join("");
  }

  function hexWithColons(hex) {
    var out = [];
    for (var i = 0; i < hex.length; i += 2) {
      out.push(hex.slice(i, i + 2));
    }
    return out.join(":");
  }

  function textFromBytes(bytes) {
    try {
      return new TextDecoder("utf-8").decode(bytes);
    } catch (e) {
      var s = "";
      for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return s;
    }
  }

  function findApkSigBlockMagic(buffer) {
    try {
      var bytes = new Uint8Array(buffer);
      var magic = "APK Sig Block 42";
      var magicBytes = [];
      for (var i = 0; i < magic.length; i++) magicBytes.push(magic.charCodeAt(i));

      var start = Math.max(0, bytes.length - 256 * 1024);
      for (var p = bytes.length - magicBytes.length; p >= start; p--) {
        var ok = true;
        for (var j = 0; j < magicBytes.length; j++) {
          if (bytes[p + j] !== magicBytes[j]) {
            ok = false;
            break;
          }
        }
        if (ok) return true;
      }
    } catch (e) {}
    return false;
  }

  function findEocdOffset(view) {
    var sig = 0x06054b50;
    var max = Math.max(0, view.byteLength - 65557);
    for (var i = view.byteLength - 22; i >= max; i--) {
      if (view.getUint32(i, true) === sig) return i;
    }
    return -1;
  }

  function parseZipCentralDirectory(buffer) {
    var view = new DataView(buffer);
    var eocd = findEocdOffset(view);
    if (eocd < 0) throw new Error("ZIP EOCD not found");

    var cdSize = view.getUint32(eocd + 12, true);
    var cdOffset = view.getUint32(eocd + 16, true);

    var entries = [];
    var off = cdOffset;
    var end = cdOffset + cdSize;
    while (off < end) {
      if (view.getUint32(off, true) !== 0x02014b50) break;

      var method = view.getUint16(off + 10, true);
      var compSize = view.getUint32(off + 20, true);
      var uncompSize = view.getUint32(off + 24, true);
      var nameLen = view.getUint16(off + 28, true);
      var extraLen = view.getUint16(off + 30, true);
      var commentLen = view.getUint16(off + 32, true);
      var localOffset = view.getUint32(off + 42, true);

      var nameBytes = new Uint8Array(buffer, off + 46, nameLen);
      var name = textFromBytes(nameBytes);

      entries.push({
        name: name,
        method: method,
        compSize: compSize,
        uncompSize: uncompSize,
        localOffset: localOffset,
      });

      off += 46 + nameLen + extraLen + commentLen;
    }
    return entries;
  }

  function findSignatureEntry(entries) {
    var candidates = [];
    for (var i = 0; i < entries.length; i++) {
      var name = entries[i].name;
      if (!name) continue;
      if (name.indexOf("META-INF/") !== 0) continue;
      if (/\.(RSA|DSA|EC)$/i.test(name)) candidates.push(entries[i]);
    }
    candidates.sort(function (a, b) {
      return a.name.localeCompare(b.name);
    });
    return candidates.length > 0 ? candidates[0] : null;
  }

  async function extractZipEntry(buffer, entry) {
    var view = new DataView(buffer);
    var off = entry.localOffset;
    if (view.getUint32(off, true) !== 0x04034b50) throw new Error("ZIP local header not found");
    var nameLen = view.getUint16(off + 26, true);
    var extraLen = view.getUint16(off + 28, true);
    var dataStart = off + 30 + nameLen + extraLen;
    var comp = new Uint8Array(buffer, dataStart, entry.compSize);

    if (entry.method === 0) return new Uint8Array(comp);
    if (entry.method !== 8) throw new Error("Unsupported ZIP compression method: " + entry.method);

    if (typeof DecompressionStream === "undefined") {
      throw new Error("Deflate decompression not supported in this browser");
    }
    var ds = new DecompressionStream("deflate-raw");
    var decompressed = await new Response(new Blob([comp]).stream().pipeThrough(ds)).arrayBuffer();
    return new Uint8Array(decompressed);
  }

  function readLength(view, offset) {
    var first = view.getUint8(offset);
    if ((first & 0x80) === 0) return { len: first, bytes: 1 };
    var count = first & 0x7f;
    var len = 0;
    for (var i = 0; i < count; i++) {
      len = (len << 8) | view.getUint8(offset + 1 + i);
    }
    return { len: len, bytes: 1 + count };
  }

  function readTlv(view, start, end) {
    if (start >= end) return null;
    var tagByte = view.getUint8(start);
    var tagClass = tagByte >> 6;
    var constructed = (tagByte & 0x20) !== 0;
    var tagNumber = tagByte & 0x1f;
    if (tagNumber === 0x1f) throw new Error("High-tag-number form not supported");

    var lenInfo = readLength(view, start + 1);
    var contentStart = start + 1 + lenInfo.bytes;
    var contentLen = lenInfo.len;
    var tlvEnd = contentStart + contentLen;
    if (tlvEnd > end) throw new Error("ASN.1 length out of bounds");

    return {
      tagClass: tagClass,
      constructed: constructed,
      tagNumber: tagNumber,
      start: start,
      contentStart: contentStart,
      contentLen: contentLen,
      end: tlvEnd,
    };
  }

  function parseChildren(view, node) {
    var children = [];
    var off = node.contentStart;
    var end = node.end;
    while (off < end) {
      var child = readTlv(view, off, end);
      if (!child) break;
      children.push(child);
      off = child.end;
    }
    return children;
  }

  function decodeOid(bytes) {
    if (bytes.length === 0) return "";
    var first = bytes[0];
    var oid = [];
    oid.push(Math.floor(first / 40));
    oid.push(first % 40);
    var value = 0;
    for (var i = 1; i < bytes.length; i++) {
      var b = bytes[i];
      value = (value << 7) | (b & 0x7f);
      if ((b & 0x80) === 0) {
        oid.push(value);
        value = 0;
      }
    }
    return oid.join(".");
  }

  function decodeBmpString(bytes) {
    var out = "";
    for (var i = 0; i + 1 < bytes.length; i += 2) {
      out += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return out;
  }

  function decodeAsn1String(view, node) {
    var bytes = new Uint8Array(view.buffer, node.contentStart, node.contentLen);
    if (node.tagNumber === 0x1e) return decodeBmpString(bytes); // BMPString
    return textFromBytes(bytes);
  }

  function decodeTime(view, node) {
    var raw = decodeAsn1String(view, node);
    var s = safeText(raw);
    if (!s) return "";
    if (node.tagNumber === 0x17 && s.length >= 13) {
      var yy = parseInt(s.slice(0, 2), 10);
      var year = yy >= 50 ? 1900 + yy : 2000 + yy;
      var iso =
        year +
        "-" +
        s.slice(2, 4) +
        "-" +
        s.slice(4, 6) +
        "T" +
        s.slice(6, 8) +
        ":" +
        s.slice(8, 10) +
        ":" +
        s.slice(10, 12) +
        "Z";
      return iso;
    }
    if (node.tagNumber === 0x18 && s.length >= 15) {
      return (
        s.slice(0, 4) +
        "-" +
        s.slice(4, 6) +
        "-" +
        s.slice(6, 8) +
        "T" +
        s.slice(8, 10) +
        ":" +
        s.slice(10, 12) +
        ":" +
        s.slice(12, 14) +
        "Z"
      );
    }
    return s;
  }

  function parseName(view, node) {
    var OID_MAP = {
      "2.5.4.3": "CN",
      "2.5.4.6": "C",
      "2.5.4.7": "L",
      "2.5.4.8": "ST",
      "2.5.4.10": "O",
      "2.5.4.11": "OU",
    };
    var parts = [];
    var rdns = parseChildren(view, node);
    for (var i = 0; i < rdns.length; i++) {
      var setNode = rdns[i];
      var attrs = parseChildren(view, setNode);
      for (var j = 0; j < attrs.length; j++) {
        var atv = attrs[j];
        var seq = parseChildren(view, atv);
        if (seq.length < 2) continue;
        var oidNode = seq[0];
        var valNode = seq[1];
        var oidBytes = new Uint8Array(view.buffer, oidNode.contentStart, oidNode.contentLen);
        var oid = decodeOid(oidBytes);
        var key = OID_MAP[oid] || oid;
        var val = decodeAsn1String(view, valNode);
        if (val) parts.push(key + "=" + val);
      }
    }
    return parts.join(", ");
  }

  async function sha256HexFromBuffer(buffer) {
    if (!window.crypto || !window.crypto.subtle) throw new Error("WebCrypto not available");
    var digest = await window.crypto.subtle.digest("SHA-256", buffer);
    return bytesToHex(new Uint8Array(digest));
  }

  function extractFirstCertificateFromPkcs7(pkcs7Bytes) {
    var view = new DataView(pkcs7Bytes.buffer, pkcs7Bytes.byteOffset, pkcs7Bytes.byteLength);
    var root = readTlv(view, 0, view.byteLength);
    if (!root || root.tagNumber !== 0x10) throw new Error("PKCS7 not a SEQUENCE");
    var rootChildren = parseChildren(view, root);
    if (rootChildren.length < 2) throw new Error("Invalid PKCS7 structure");

    var oidNode = rootChildren[0];
    var oidBytes = new Uint8Array(view.buffer, oidNode.contentStart, oidNode.contentLen);
    var oid = decodeOid(oidBytes);
    if (oid !== "1.2.840.113549.1.7.2") throw new Error("Not SignedData (OID " + oid + ")");

    var contentNode = rootChildren[1];
    var contentChildren = parseChildren(view, contentNode);
    if (contentChildren.length === 0) throw new Error("Missing SignedData content");
    var signedData = contentChildren[0];
    var sdChildren = parseChildren(view, signedData);

    var certsNode = null;
    for (var i = 0; i < sdChildren.length; i++) {
      var n = sdChildren[i];
      if (n.tagClass === 2 && n.tagNumber === 0) {
        certsNode = n;
        break;
      }
    }
    if (!certsNode) throw new Error("No certificates found in SignedData");

    var certCandidates = parseChildren(view, certsNode);
    for (var c = 0; c < certCandidates.length; c++) {
      var cert = certCandidates[c];
      if (cert.tagNumber === 0x10) {
        var certBytes = new Uint8Array(view.buffer, cert.start, cert.end - cert.start);
        return certBytes;
      }
    }
    throw new Error("Certificate parsing failed");
  }

  function parseX509Certificate(certBytes) {
    var view = new DataView(certBytes.buffer, certBytes.byteOffset, certBytes.byteLength);
    var root = readTlv(view, 0, view.byteLength);
    if (!root || root.tagNumber !== 0x10) throw new Error("X509 not a SEQUENCE");
    var rootChildren = parseChildren(view, root);
    if (rootChildren.length < 1) throw new Error("Invalid X509 structure");
    var tbs = rootChildren[0];
    var tbsChildren = parseChildren(view, tbs);
    var idx = 0;
    if (tbsChildren[idx] && tbsChildren[idx].tagClass === 2 && tbsChildren[idx].tagNumber === 0) {
      idx++;
    }
    idx++; // serialNumber
    idx++; // signature algorithm
    var issuer = tbsChildren[idx++];
    var validity = tbsChildren[idx++];
    var subject = tbsChildren[idx++];

    var issuerStr = issuer ? parseName(view, issuer) : "";
    var subjectStr = subject ? parseName(view, subject) : "";
    var notBefore = "";
    var notAfter = "";
    if (validity) {
      var vChildren = parseChildren(view, validity);
      if (vChildren[0]) notBefore = decodeTime(view, vChildren[0]);
      if (vChildren[1]) notAfter = decodeTime(view, vChildren[1]);
    }
    return {
      issuer: issuerStr,
      subject: subjectStr,
      notBefore: notBefore,
      notAfter: notAfter,
    };
  }

  async function computeSignature(file) {
    var result = {
      apkSha256: "",
      schemes: { v1: false, v2: false, v3: false },
      primaryCert: null,
      certError: "",
    };
    try {
      var buffer = await file.arrayBuffer();
      result.apkSha256 = await sha256HexFromBuffer(buffer);
      result.apkSha256 = result.apkSha256 ? result.apkSha256 : "";
      result.schemes.v2 = findApkSigBlockMagic(buffer);

      var entries = parseZipCentralDirectory(buffer);
      var sigEntry = findSignatureEntry(entries);
      result.schemes.v1 = !!sigEntry;

      if (sigEntry) {
        try {
          var pkcs7 = await extractZipEntry(buffer, sigEntry);
          var certDer = extractFirstCertificateFromPkcs7(pkcs7);
          var certHash = await sha256HexFromBuffer(certDer.buffer.slice(certDer.byteOffset, certDer.byteOffset + certDer.byteLength));
          var certInfo = parseX509Certificate(certDer);
          result.primaryCert = {
            fingerprintSha256: hexWithColons(certHash),
            subject: certInfo.subject,
            issuer: certInfo.issuer,
            notBefore: certInfo.notBefore,
            notAfter: certInfo.notAfter,
          };
        } catch (e) {
          result.certError = safeText(e && e.message) || "Certificate parsing failed";
        }
      }
    } catch (e) {
      result.certError = safeText(e && e.message) || "Signature scan failed";
    }
    return result;
  }

  function reset() {
    ensureUi();
    current.summary = null;
    current.findings = [];
    current.exportedComponents = [];
    current.meta = null;
    current.signature = null;
    if (ui.search) ui.search.value = "";
    if (ui.list) ui.list.innerHTML = "";
    if (ui.signatureSummary) ui.signatureSummary.textContent = "";
    if (ui.signatureDetails) ui.signatureDetails.innerHTML = "";
    if (ui.exportedSearch) ui.exportedSearch.value = "";
    if (ui.exportedList) ui.exportedList.innerHTML = "";
    if (ui.exportedCount) ui.exportedCount.textContent = "";
    if (ui.downloadReport) ui.downloadReport.disabled = true;
    if (ui.downloadPdf) ui.downloadPdf.disabled = true;
    if (ui.card) ui.card.style.display = "none";
  }

  window.SecurityScanner = {
    analyze: analyze,
    render: render,
    reset: reset,
    computeSignature: computeSignature,
    getSummary: function () {
      return current.summary;
    },
    getSignature: function () {
      return current.signature;
    },
    getReport: buildReportObject,
  };

  document.addEventListener("DOMContentLoaded", function () {
    ensureUi();
  });
})();
