(function () {
  var STORAGE_KEY_GEMINI_API_KEY = "trustify_gemini_api_key";
  var MODEL = "gemini-2.5-flash";
  var API_BASE = "https://generativelanguage.googleapis.com/v1beta/models/";

  var ui = {};
  var messages = [];
  var isSending = false;

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

  function escapeHtml(value) {
    return safeText(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
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
          escapeHtml(message.text).replace(/\n/g, "<br>") +
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
      ui.send.textContent = sending ? "Thinking" : "Send";
    }
    if (ui.input) ui.input.disabled = sending;
  }

  function buildGeminiPayload(userMessage) {
    var context = collectScanContext();
    var history = messages.slice(-8).map(function (message) {
      return {
        role: message.role === "user" ? "user" : "model",
        parts: [{ text: message.text }],
      };
    });

    return {
      systemInstruction: {
        parts: [
          {
            text:
              "You are Trustify's explainable APK security assistant. Answer with practical, concise explanations grounded only in the provided analysis context. Explain why something matters, cite the exact signals you used, and call out uncertainty when data is missing. Do not claim the APK is safe or malicious with certainty. If there is no scan context yet, help the user understand what they can ask after analyzing an APK.",
          },
        ],
      },
      contents: history.concat([
        {
          role: "user",
          parts: [
            {
              text:
                contextToPrompt(context) +
                "\n\nUser question:\n" +
                userMessage +
                "\n\nAnswer in 3-6 short paragraphs or bullets. Include an 'Evidence used' line when you mention a risk.",
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

    var response = await fetch(API_BASE + MODEL + ":generateContent?key=" + encodeURIComponent(key), {
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
    ui.keyForm = $("ai-chatbot-key-form");
    ui.keyInput = $("ai-chatbot-key");

    if (!ui.root || !ui.toggle || !ui.panel) return;

    ui.toggle.addEventListener("click", function () {
      setOpen(ui.panel.hidden);
    });
    if (ui.close) ui.close.addEventListener("click", function () { setOpen(false); });
    if (ui.form) ui.form.addEventListener("submit", handleSubmit);
    if (ui.keyForm) ui.keyForm.addEventListener("submit", handleKeySubmit);
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
