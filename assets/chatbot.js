(function () {
  var STORAGE_KEY_GEMINI_API_KEY = "trustify_gemini_api_key";
  var STORAGE_KEY_GEMINI_MODEL = "trustify_gemini_model";
  var DEFAULT_MODEL = "gemini-2.5-flash";
  var MODELS = {
    "gemini-2.5-flash": "Gemini 2.5 Flash",
    "gemini-2.5-flash-lite": "Gemini 2.5 Flash Lite",
  };
  var API_BASE = "https://generativelanguage.googleapis.com/v1beta/models/";

  var ui = {};
  var messages = [];
  var isSending = false;
  var useApkContext = true;

  function $(id) {
    return document.getElementById(id);
  }

  function safeText(value) {
    return (value == null ? "" : String(value)).trim();
  }

  function getApiKey() {
    if (window.AccountManager && typeof window.AccountManager.getGeminiApiKey === "function") {
      return window.AccountManager.getGeminiApiKey();
    }
    try {
      return localStorage.getItem(STORAGE_KEY_GEMINI_API_KEY) || "";
    } catch (e) {
      return "";
    }
  }

  function saveApiKey(apiKey) {
    if (window.AccountManager && typeof window.AccountManager.saveGeminiApiKey === "function") {
      return window.AccountManager.saveGeminiApiKey(apiKey);
    }
    try {
      var key = safeText(apiKey);
      if (key) localStorage.setItem(STORAGE_KEY_GEMINI_API_KEY, key);
      else localStorage.removeItem(STORAGE_KEY_GEMINI_API_KEY);
      window.dispatchEvent(new CustomEvent("trustify:gemini-key-updated"));
      return true;
    } catch (e) {
      alert("Could not save Gemini API key in this browser.");
      return false;
    }
  }
  function getSelectedModel() {
    var selected = ui.modelSelect ? ui.modelSelect.value : "";
    if (MODELS[selected]) return selected;
    try {
      var stored = localStorage.getItem(STORAGE_KEY_GEMINI_MODEL) || "";
      if (MODELS[stored]) return stored;
    } catch (e) {}
    return DEFAULT_MODEL;
  }

  function setSelectedModel(model) {
    var nextModel = MODELS[model] ? model : DEFAULT_MODEL;
    if (ui.modelSelect) ui.modelSelect.value = nextModel;
    if (ui.modelCurrent) ui.modelCurrent.textContent = MODELS[nextModel];
    if (ui.modelOptions) {
      ui.modelOptions.forEach(function (option) {
        option.setAttribute("aria-selected", option.dataset.model === nextModel ? "true" : "false");
      });
    }
    try {
      localStorage.setItem(STORAGE_KEY_GEMINI_MODEL, nextModel);
    } catch (e) {}
  }

  function setModelMenuOpen(open) {
    if (!ui.modelMenu || !ui.modelTrigger) return;
    ui.modelMenu.hidden = !open;
    ui.modelTrigger.setAttribute("aria-expanded", open ? "true" : "false");
  }

  function getApkReferenceName() {
    return textFrom("app-label") || textFrom("file-name") || "Current APK";
  }

  function updateApkContextIcon() {
    if (!ui.contextApkIcon) return;
    var appIcon = $("app-icon");
    var iconSrc = appIcon && appIcon.getAttribute("src") ? appIcon.getAttribute("src") : "";
    if (iconSrc && appIcon.style.display !== "none") {
      ui.contextApkIcon.src = iconSrc;
      ui.contextApkIcon.hidden = false;
    } else {
      ui.contextApkIcon.removeAttribute("src");
      ui.contextApkIcon.hidden = true;
    }
  }

  function setApkContextEnabled(enabled) {
    useApkContext = !!enabled;
    if (ui.contextToggle) {
      ui.contextToggle.setAttribute("aria-pressed", useApkContext ? "true" : "false");
      ui.contextToggle.title = useApkContext ? "Remove APK context" : "Use current APK as reference";
    }
    if (ui.contextLabel) {
      ui.contextLabel.textContent = useApkContext ? getApkReferenceName() : "General questions mode";
    }
    if (ui.input) {
      ui.input.placeholder = useApkContext
        ? "Ask about permissions, findings, or the manifest..."
        : "Ask a general security or Android question...";
    }
    updateApkContextIcon();
  }

  function escapeHtml(value) {
    return safeText(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function renderInlineMarkdown(text) {
    return escapeHtml(text)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\*([^*\n]+)\*/g, "<strong>$1</strong>");
  }

  function renderMarkdown(text) {
    var lines = safeText(text).split(/\n/);
    var html = [];
    var inList = false;

    lines.forEach(function (line) {
      var trimmed = line.trim();
      var bulletMatch = trimmed.match(/^[*-]\s+(.+)$/);

      if (bulletMatch) {
        if (!inList) {
          html.push("<ul>");
          inList = true;
        }
        html.push("<li>" + renderInlineMarkdown(bulletMatch[1]) + "</li>");
        return;
      }

      if (inList) {
        html.push("</ul>");
        inList = false;
      }

      if (!trimmed) {
        html.push("<br>");
        return;
      }

      html.push("<p>" + renderInlineMarkdown(trimmed) + "</p>");
    });

    if (inList) html.push("</ul>");
    return html.join("");
  }

  function textFrom(id) {
    var el = $(id);
    if (!el || el.style.display === "none") return "";
    return safeText(el.textContent || el.innerText || "");
  }

  function trimBlock(text, maxLength) {
    var value = safeText(text).replace(/\s+\n/g, "\n");
    if (value.length <= maxLength) return value;
    return value.slice(0, maxLength) + "\n...[truncated]";
  }

  function collectScanContext() {
    var context = {
      appLabel: textFrom("app-label"),
      packageName: textFrom("package-name"),
      versionCode: textFrom("version-code"),
      versionName: textFrom("version-name"),
      minSdk: textFrom("min-sdk"),
      targetSdk: textFrom("target-sdk"),
      permissions: trimBlock(textFrom("permissions-list"), 4000),
      activities: trimBlock(textFrom("activities-list"), 1800),
      services: trimBlock(textFrom("services-list"), 1800),
      receivers: trimBlock(textFrom("receivers-list"), 1800),
      providers: trimBlock(textFrom("providers-list"), 1800),
      manifest: trimBlock(textFrom("android-manifest"), 6000),
      strings: trimBlock(textFrom("values-strings"), 2000),
      securitySummary: "",
      securityFindings: trimBlock(textFrom("security-findings"), 4000),
      virusTotal: trimBlock(textFrom("virustotal-details"), 2500),
      exportedComponents: trimBlock(textFrom("exported-components"), 3000),
      signature: trimBlock(textFrom("signature-details"), 2500),
    };

    if (window.SecurityScanner && typeof window.SecurityScanner.getSummary === "function") {
      try {
        context.securitySummary = JSON.stringify(window.SecurityScanner.getSummary() || null);
      } catch (e) {}
    }

    return context;
  }

  function contextToPrompt(context) {
    return [
      "Current Trustify APK analysis context:",
      "App label: " + (context.appLabel || "unknown"),
      "Package: " + (context.packageName || "unknown"),
      "Version code: " + (context.versionCode || "unknown"),
      "Version name: " + (context.versionName || "unknown"),
      "minSdk: " + (context.minSdk || "unknown"),
      "targetSdk: " + (context.targetSdk || "unknown"),
      "Security summary: " + (context.securitySummary || "not available"),
      "Signature: " + (context.signature || "not available"),
      "Permissions:\n" + (context.permissions || "not available"),
      "Security findings:\n" + (context.securityFindings || "not available"),
      "VirusTotal:\n" + (context.virusTotal || "not available"),
      "Exported components:\n" + (context.exportedComponents || "not available"),
      "Activities:\n" + (context.activities || "not available"),
      "Services:\n" + (context.services || "not available"),
      "Receivers:\n" + (context.receivers || "not available"),
      "Providers:\n" + (context.providers || "not available"),
      "Manifest excerpt:\n" + (context.manifest || "not available"),
      "Strings excerpt:\n" + (context.strings || "not available"),
    ].join("\n\n");
  }

  function setOpen(open) {
    if (!ui.panel || !ui.toggle) return;
    ui.panel.hidden = !open;
    ui.toggle.setAttribute("aria-expanded", open ? "true" : "false");
    ui.root.classList.toggle("ai-chatbot--open", open);
    if (open && ui.input) ui.input.focus();
  }

  function updateKeyForm() {
    var hasKey = !!getApiKey();
    if (ui.keyForm) ui.keyForm.hidden = hasKey;
    if (ui.keyInput) ui.keyInput.value = "";
  }

  function addMessage(role, text) {
    messages.push({ role: role, text: text });
    renderMessages();
  }

  function renderMessages() {
    if (!ui.messages) return;
    if (messages.length === 0) {
      ui.messages.innerHTML =
        "<div class='ai-chatbot__empty'>Ask me to explain risk, permissions, exported components, or what to review next.</div>";
      return;
    }
    ui.messages.innerHTML = messages
      .map(function (message) {
        return (
          "<div class='ai-message ai-message--" +
          escapeHtml(message.role) +
          "'><div class='ai-message__label'>" +
          (message.role === "user" ? "You" : "Assistant") +
          "</div><div class='ai-message__body'>" +
          renderMarkdown(message.text) +
          "</div></div>"
        );
      })
      .join("");
    ui.messages.scrollTop = ui.messages.scrollHeight;
  }

  function setSending(sending) {
    isSending = sending;
    if (ui.send) {
      ui.send.disabled = sending;
      ui.send.classList.toggle("ai-chatbot__send--loading", sending);
      ui.send.setAttribute("aria-label", sending ? "Thinking" : "Send message");
      ui.send.title = sending ? "Thinking" : "Send message";
    }
    if (ui.input) ui.input.disabled = sending;
  }

  function buildGeminiPayload(userMessage) {
    var context = useApkContext ? collectScanContext() : null;
    var history = messages.slice(-8).map(function (message) {
      return {
        role: message.role === "user" ? "user" : "model",
        parts: [{ text: message.text }],
      };
    });
    var instruction = useApkContext
      ? "You are Trustify's explainable APK security assistant. Answer with practical, concise explanations grounded only in the provided analysis context. Explain why something matters, cite the exact signals you used, and call out uncertainty when data is missing. Do not claim the APK is safe or malicious with certainty. If there is no scan context yet, help the user understand what they can ask after analyzing an APK."
      : "You are Trustify's AI assistant. The user has turned off APK context for this message, so answer general Android, APK, and security questions without referring to any current scan unless the user explicitly provides details. Keep answers practical and concise.";
    var prompt = useApkContext
      ? contextToPrompt(context) +
        "\n\nUser question:\n" +
        userMessage +
        "\n\nAnswer in 3-6 short paragraphs or bullets. Include an 'Evidence used' line when you mention a risk."
      : "User question:\n" + userMessage + "\n\nAnswer in 3-6 short paragraphs or bullets.";

    return {
      systemInstruction: {
        parts: [
          {
            text: instruction,
          },
        ],
      },
      contents: history.concat([
        {
          role: "user",
          parts: [
            {
              text: prompt,
            },
          ],
        },
      ]),
      generationConfig: {
        temperature: 0.25,
        topP: 0.9,
        maxOutputTokens: 900,
      },
    };
  }

  function extractGeminiText(data) {
    var candidate = data && data.candidates && data.candidates[0];
    var parts = candidate && candidate.content && candidate.content.parts;
    if (!parts || !parts.length) return "";
    return parts
      .map(function (part) {
        return part.text || "";
      })
      .join("\n")
      .trim();
  }

  async function askGemini(userMessage) {
    var key = getApiKey();
    if (!key) {
      updateKeyForm();
      throw new Error("Add a Gemini API key first, either here or in Account & History.");
    }

    var model = getSelectedModel();
    var response = await fetch(API_BASE + model + ":generateContent?key=" + encodeURIComponent(key), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildGeminiPayload(userMessage)),
    });

    var data = await response.json().catch(function () {
      return null;
    });

    if (!response.ok) {
      var message =
        data && data.error && data.error.message
          ? data.error.message
          : "Gemini request failed with status " + response.status + ".";
      throw new Error(message);
    }

    return extractGeminiText(data) || "Gemini returned an empty response.";
  }

  async function handleSubmit(event) {
    event.preventDefault();
    if (isSending || !ui.input) return;
    var text = safeText(ui.input.value);
    if (!text) return;

    ui.input.value = "";
    addMessage("user", text);
    setSending(true);

    try {
      var answer = await askGemini(text);
      addMessage("assistant", answer);
    } catch (e) {
      addMessage("assistant", "I could not complete that request. " + (e && e.message ? e.message : "Please try again."));
    } finally {
      setSending(false);
      updateKeyForm();
    }
  }

  function handleKeySubmit(event) {
    event.preventDefault();
    if (!ui.keyInput) return;
    if (saveApiKey(ui.keyInput.value)) {
      updateKeyForm();
      addMessage("assistant", "Gemini API key saved locally. You can ask me about the APK analysis now.");
      if (ui.input) ui.input.focus();
    }
  }

  function init() {
    ui.root = $("ai-chatbot");
    ui.toggle = $("ai-chatbot-toggle");
    ui.panel = $("ai-chatbot-panel");
    ui.close = $("ai-chatbot-close");
    ui.messages = $("ai-chatbot-messages");
    ui.form = $("ai-chatbot-form");
    ui.input = $("ai-chatbot-input");
    ui.send = $("ai-chatbot-send");
    ui.modelSelect = $("ai-chatbot-model");
    ui.modelTrigger = $("ai-chatbot-model-trigger");
    ui.modelCurrent = $("ai-chatbot-model-current");
    ui.modelMenu = $("ai-chatbot-model-menu");
    ui.modelOptions = Array.prototype.slice.call(document.querySelectorAll(".ai-chatbot__model-option"));
    ui.contextToggle = $("ai-chatbot-context-toggle");
    ui.contextLabel = $("ai-chatbot-context-label");
    ui.contextApkIcon = $("ai-chatbot-context-apk-icon");
    ui.keyForm = $("ai-chatbot-key-form");
    ui.keyInput = $("ai-chatbot-key");

    if (!ui.root || !ui.toggle || !ui.panel) return;

    ui.toggle.addEventListener("click", function () {
      setOpen(ui.panel.hidden);
    });
    if (ui.close) ui.close.addEventListener("click", function () { setOpen(false); });
    if (ui.form) ui.form.addEventListener("submit", handleSubmit);
    if (ui.keyForm) ui.keyForm.addEventListener("submit", handleKeySubmit);
    if (ui.modelSelect) {
      setSelectedModel(getSelectedModel());
      ui.modelSelect.addEventListener("change", function () {
        setSelectedModel(ui.modelSelect.value);
      });
    }
    if (ui.modelTrigger) {
      ui.modelTrigger.addEventListener("click", function () {
        setModelMenuOpen(ui.modelMenu.hidden);
      });
    }
    if (ui.modelOptions) {
      ui.modelOptions.forEach(function (option) {
        option.addEventListener("click", function () {
          setSelectedModel(option.dataset.model);
          setModelMenuOpen(false);
        });
      });
    }
    document.addEventListener("click", function (event) {
      if (ui.modelMenu && ui.modelTrigger && !ui.modelMenu.hidden && !event.target.closest(".ai-chatbot__model-picker")) {
        setModelMenuOpen(false);
      }
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") setModelMenuOpen(false);
    });
    if (ui.contextToggle) {
      ui.contextToggle.addEventListener("click", function () {
        setApkContextEnabled(!useApkContext);
      });
      setApkContextEnabled(useApkContext);
      ["app-label", "file-name", "app-icon"].forEach(function (id) {
        var target = $(id);
        if (!target || typeof MutationObserver !== "function") return;
        new MutationObserver(function () {
          if (useApkContext) setApkContextEnabled(true);
          else updateApkContextIcon();
        }).observe(target, { attributes: true, childList: true, characterData: true, subtree: true });
      });
    }
    if (ui.input) {
      ui.input.addEventListener("keydown", function (event) {
        if (event.key === "Enter" && !event.shiftKey) {
          event.preventDefault();
          ui.form.dispatchEvent(new Event("submit", { cancelable: true }));
        }
      });
    }
    window.addEventListener("trustify:gemini-key-updated", updateKeyForm);

    renderMessages();
    updateKeyForm();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
