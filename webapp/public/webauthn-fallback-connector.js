(function () {
  var params = new URLSearchParams(window.location.search);
  var sentSuccess = false;
  var allowedParentOriginsPromise = null;

  var text = pickText(params.get("locale") || navigator.language || "en");
  document.documentElement.lang = params.get("locale") || navigator.language || "en";

  var titleEl = document.getElementById("title");
  var subtitleEl = document.getElementById("subtitle");
  var rememberEl = document.getElementById("remember");
  var rememberLabelEl = document.getElementById("remember-label");
  var buttonEl = document.getElementById("webauthn-button");
  var msgEl = document.getElementById("msg");

  titleEl.textContent = text.title;
  subtitleEl.textContent = text.subtitle;
  rememberLabelEl.textContent = text.remember;
  buttonEl.textContent = decodeRepeated(params.get("btnText")) || text.button;

  buttonEl.addEventListener("click", start);

  function pickText(locale) {
    var normalized = String(locale || "en").toLowerCase();
    if (normalized.indexOf("zh") === 0) {
      return {
        title: "\u9a8c\u8bc1\u8eab\u4efd",
        subtitle: "\u4f7f\u7528\u5b89\u5168\u5bc6\u94a5\u5b8c\u6210\u4e24\u6b65\u9a8c\u8bc1\u3002",
        remember: "30 \u5929\u5185\u4fe1\u4efb\u6b64\u8bbe\u5907",
        button: "\u8bfb\u53d6\u5b89\u5168\u5bc6\u94a5",
        awaiting: "\u7b49\u5f85\u5b89\u5168\u5bc6\u94a5\u4ea4\u4e92...",
        success: "\u9a8c\u8bc1\u5b8c\u6210",
        unsupported: "\u5f53\u524d\u6d4f\u89c8\u5668\u4e0d\u652f\u6301\u5b89\u5168\u5bc6\u94a5",
      };
    }
    return {
      title: "Verify your identity",
      subtitle: "Use your security key to finish two-step verification.",
      remember: "Trust this device for 30 days",
      button: "Read security key",
      awaiting: "Awaiting security key interaction...",
      success: "Verification complete",
      unsupported: "This browser does not support security keys",
    };
  }

  function decodeRepeated(value) {
    if (!value) return "";
    var out = String(value);
    for (var i = 0; i < 2; i += 1) {
      try {
        var next = decodeURIComponent(out);
        if (next === out) break;
        out = next;
      } catch (_error) {
        break;
      }
    }
    return out;
  }

  function normalizeOrigin(value) {
    if (!value) return "";
    try {
      var url = new URL(value);
      if (!url.protocol || !url.host) return "";
      return url.protocol + "//" + url.host;
    } catch (_error) {
      return "";
    }
  }

  function isExtensionOrigin(origin) {
    return (
      origin.indexOf("chrome-extension://") === 0 ||
      origin.indexOf("moz-extension://") === 0 ||
      origin.indexOf("safari-web-extension://") === 0
    );
  }

  function allowedParentOrigins() {
    if (allowedParentOriginsPromise) return allowedParentOriginsPromise;
    allowedParentOriginsPromise = fetch("/api/web-bootstrap", {
      headers: { Accept: "application/json" },
      credentials: "omit",
    }).then(function (response) {
      if (!response.ok) return [];
      return response.json();
    }).then(function (body) {
      var origins = Array.isArray(body && body.webAuthnAllowedOrigins)
        ? body.webAuthnAllowedOrigins
        : [];
      return origins.map(normalizeOrigin).filter(Boolean);
    }).catch(function () {
      return [];
    });
    return allowedParentOriginsPromise;
  }

  function trustedParentOrigin(allowedOrigins) {
    var parent = decodeRepeated(params.get("parent"));
    if (!parent) return "";
    var parentOrigin = normalizeOrigin(parent);
    if (!parentOrigin) return "";
    if (parentOrigin === window.location.origin) {
      return parentOrigin;
    }
    if (isExtensionOrigin(parentOrigin) && allowedOrigins.indexOf(parentOrigin) >= 0) {
      return parentOrigin;
    }
    return "";
  }

  function safeShallowCopy(source) {
    var copy = {};
    if (!source || typeof source !== "object") return copy;
    Object.keys(source).forEach(function (key) {
      if (key === "__proto__" || key === "prototype" || key === "constructor") return;
      copy[key] = source[key];
    });
    return copy;
  }

  async function postResult(message) {
    var parentOrigin = trustedParentOrigin(await allowedParentOrigins());
    if (parentOrigin) {
      if (window.opener && !window.opener.closed) {
        window.opener.postMessage(message, parentOrigin);
      }
      if (window.parent && window.parent !== window) {
        window.parent.postMessage(message, parentOrigin);
      }
    }
    window.postMessage(message, window.location.origin);
  }

  function showMessage(kind, message) {
    msgEl.textContent = String(message || "");
    msgEl.className = "msg show " + kind;
  }

  function decodeBase64Unicode(value) {
    var input = String(value || "").replace(/ /g, "+");
    try {
      return decodeURIComponent(Array.prototype.map.call(atob(input), function (char) {
        return "%" + ("00" + char.charCodeAt(0).toString(16)).slice(-2);
      }).join(""));
    } catch (_error) {
      var normalized = input.replace(/-/g, "+").replace(/_/g, "/");
      normalized += "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
      return decodeURIComponent(Array.prototype.map.call(atob(normalized), function (char) {
        return "%" + ("00" + char.charCodeAt(0).toString(16)).slice(-2);
      }).join(""));
    }
  }

  function bytesFromBase64Url(value) {
    var normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
    normalized += "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
    var binary = atob(normalized);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function base64UrlFromBuffer(value) {
    if (!value) return undefined;
    var bytes = value instanceof Uint8Array
      ? value
      : new Uint8Array(value);
    var binary = "";
    for (var i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function readPublicKeyOptions() {
    var data = params.get("data");
    if (!data) throw new Error("No data.");
    var decoded = decodeBase64Unicode(data);
    if (params.get("v") === "1") {
      return JSON.parse(decoded);
    }
    var payload = JSON.parse(decoded);
    return typeof payload.data === "string" ? JSON.parse(payload.data) : payload.data;
  }

  function normalizeOptions(options) {
    if (!options || typeof options !== "object") throw new Error("Cannot parse data.");
    var copy = safeShallowCopy(options);
    copy.challenge = bytesFromBase64Url(copy.challenge);
    if (Array.isArray(copy.allowCredentials)) {
      copy.allowCredentials = copy.allowCredentials.map(function (credential) {
        var next = safeShallowCopy(credential);
        next.id = bytesFromBase64Url(credential && credential.id);
        return next;
      });
    }
    return copy;
  }

  function credentialToDataString(credential) {
    var response = credential.response;
    var clientDataJSON = base64UrlFromBuffer(response.clientDataJSON);
    var data = {
      id: credential.id,
      rawId: base64UrlFromBuffer(credential.rawId),
      type: credential.type,
      extensions: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
      response: {
        authenticatorData: base64UrlFromBuffer(response.authenticatorData),
        clientDataJson: clientDataJSON,
        clientDataJSON: clientDataJSON,
        signature: base64UrlFromBuffer(response.signature),
        userHandle: response.userHandle ? base64UrlFromBuffer(response.userHandle) : undefined,
      },
    };
    return JSON.stringify(data);
  }

  async function start() {
    if (sentSuccess) return;
    if (!("credentials" in navigator) || !window.PublicKeyCredential) {
      showMessage("error", text.unsupported);
      return;
    }

    try {
      msgEl.className = "msg";
      buttonEl.disabled = true;
      buttonEl.textContent = decodeRepeated(params.get("btnAwaitingInteractionText")) || text.awaiting;
      var publicKey = normalizeOptions(readPublicKeyOptions());
      var credential = await navigator.credentials.get({ publicKey: publicKey });
      if (!(credential instanceof PublicKeyCredential)) {
        throw new Error("No security key was selected.");
      }
      await postResult({
        command: "webAuthnResult",
        data: credentialToDataString(credential),
        remember: rememberEl.checked,
      });
      sentSuccess = true;
      showMessage("success", text.success);
    } catch (error) {
      buttonEl.disabled = false;
      buttonEl.textContent = decodeRepeated(params.get("btnText")) || text.button;
      showMessage("error", error && error.message ? error.message : String(error || "WebAuthn failed."));
    }
  }
})();
