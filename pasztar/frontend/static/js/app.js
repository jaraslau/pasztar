const storeKey = "pasztar.identity";
const pendingKey = "pasztar.pendingIdentity";
const selectedKey = "pasztar.selectedClient";
const maxRecordingMs = 60000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  identity: null,
  clients: [],
  messages: [],
  selected: null,
  refreshing: false,
  marking: new Set(),
  recording: null,
  audioUrls: [],
};

const savedIdentity = localStorage.getItem(storeKey);
if (!savedIdentity) {
  location.replace("/setup.html");
}

const els = {
  appStatus: document.querySelector("#app-status"),
  clients: document.querySelector("#clients"),
  refreshClients: document.querySelector("#refresh-clients"),
  openSettings: document.querySelector("#open-settings"),
  closeSettings: document.querySelector("#close-settings"),
  settingsModal: document.querySelector("#settings-modal"),
  identitySummary: document.querySelector("#identity-summary"),
  chatTitle: document.querySelector("#chat-title"),
  messages: document.querySelector("#messages"),
  exportIdentity: document.querySelector("#export-identity"),
  resetIdentity: document.querySelector("#reset-identity"),
  messageForm: document.querySelector("#message-form"),
  messageText: document.querySelector("#message-text"),
  sendText: document.querySelector("#send-text"),
  recordVoice: document.querySelector("#record-voice"),
  voiceControls: document.querySelector("#voice-controls"),
  voiceTimer: document.querySelector("#voice-timer"),
  cancelVoice: document.querySelector("#cancel-voice"),
  sendVoice: document.querySelector("#send-voice"),
  clientTemplate: document.querySelector("#client-template"),
};

function b64(bytes) {
  const data = new Uint8Array(bytes);
  let binary = "";
  for (let index = 0; index < data.length; index += 0x8000) {
    binary += String.fromCharCode(...data.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function bytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

async function bundleKey(passphrase, salt, usages) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 250000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

async function sha256Hex(data) {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function fingerprint(publicKey) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(publicKey));
  return [...new Uint8Array(hash)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function status(text, error = false) {
  els.appStatus.textContent = text;
  els.appStatus.classList.toggle("error", error);
}

async function signingPrivateKey() {
  return crypto.subtle.importKey(
    "pkcs8",
    bytes(state.identity.signingPrivateKey),
    "Ed25519",
    false,
    ["sign"],
  );
}

async function encryptionPrivateKey() {
  return crypto.subtle.importKey(
    "pkcs8",
    bytes(state.identity.encryptionPrivateKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey"],
  );
}

async function encryptionPublicKey(value) {
  return crypto.subtle.importKey(
    "spki",
    bytes(value),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
}

function saveIdentity(identity) {
  state.identity = identity;
  status(`Loaded ${identity.clientId} (${identity.fingerprint.slice(0, 12)})`);
  els.identitySummary.textContent = `${identity.clientId} (${identity.fingerprint.slice(0, 12)})`;
}

async function exportIdentity() {
  const passphrase = prompt("Identity bundle passphrase");
  if (!passphrase) {
    return;
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await bundleKey(passphrase, salt, ["encrypt"]);
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(state.identity)),
  );
  const bundle = {
    v: 1,
    type: "pasztar.identity.encrypted",
    alg: "AES-GCM",
    kdf: "PBKDF2-SHA256",
    iterations: 250000,
    salt: b64(salt),
    iv: b64(iv),
    data: b64(data),
  };
  const blob = new Blob([JSON.stringify(bundle, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `pasztar-${state.identity.clientId}-identity.encrypted.json`;
  link.click();
  URL.revokeObjectURL(url);
  status("Identity bundle exported.");
}

function resetIdentity() {
  localStorage.removeItem(storeKey);
  localStorage.removeItem(pendingKey);
  localStorage.removeItem(selectedKey);
  location.replace("/setup.html");
}

function openSettings() {
  els.settingsModal.showModal();
}

function closeSettings() {
  els.settingsModal.close();
}

function loadIdentity() {
  try {
    saveIdentity(JSON.parse(savedIdentity));
    refresh().catch((error) => status(error.message, true));
  } catch {
    localStorage.removeItem(storeKey);
    location.replace("/setup.html");
  }
}

async function signedFetch(path, options = {}) {
  if (!state.identity) {
    throw new Error("Create or load an identity first.");
  }

  const method = options.method || "GET";
  const body = options.body || "";
  const timestamp = new Date().toISOString();
  const nonce = crypto.randomUUID();
  const payload = [
    method,
    path,
    timestamp,
    nonce,
    await sha256Hex(encoder.encode(body)),
  ].join("\n");
  const signature = await crypto.subtle.sign(
    "Ed25519",
    await signingPrivateKey(),
    encoder.encode(payload),
  );

  return fetch(`/api${path}`, {
    ...options,
    method,
    body: body || undefined,
    headers: {
      "Content-Type": "application/json",
      "X-Client-Id": state.identity.clientId,
      "X-Timestamp": timestamp,
      "X-Nonce": nonce,
      "X-Signature": b64(signature),
      ...(options.headers || {}),
    },
  });
}

async function apiJson(response) {
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(data?.detail || response.statusText);
  }
  return data;
}

async function loadClients() {
  state.clients = await apiJson(await signedFetch("/clients"));
  const selectedId = state.selected?.id || localStorage.getItem(selectedKey);
  if (selectedId) {
    state.selected = state.clients.find((client) => client.id === selectedId) || null;
    if (!state.selected) {
      localStorage.removeItem(selectedKey);
      els.chatTitle.textContent = "Select a client";
      els.messages.replaceChildren();
    }
  }
  if (state.selected) {
    els.chatTitle.textContent = state.selected.display_name;
  }
  renderClients();
}

function isIncoming(message) {
  return message.recipient_id === state.identity.clientId;
}

function peerId(message) {
  return message.sender_id === state.identity.clientId
    ? message.recipient_id
    : message.sender_id;
}

function messageState(message) {
  if (message.read_at) {
    return "read";
  }
  if (message.delivered_at) {
    return "delivered";
  }
  return "sent";
}

function unreadCount(clientId) {
  return state.messages.filter(
    (message) =>
      isIncoming(message) && message.sender_id === clientId && !message.read_at,
  ).length;
}

async function markMessage(message, stateName) {
  const key = `${stateName}:${message.id}`;
  if (state.marking.has(key)) {
    return;
  }
  state.marking.add(key);
  try {
    const updated = await apiJson(
      await signedFetch(
        `/messages/${encodeURIComponent(message.id)}/${stateName}`,
        { method: "POST" },
      ),
    );
    message.delivered_at = updated.delivered_at || message.delivered_at;
    message.read_at = updated.read_at || message.read_at;
  } finally {
    state.marking.delete(key);
  }
}

async function syncMessageState() {
  const tasks = [];
  for (const message of state.messages) {
    if (!isIncoming(message)) {
      continue;
    }
    tasks.push(
      (async () => {
        if (!message.delivered_at) {
          await markMessage(message, "delivered");
        }
        if (state.selected?.id === message.sender_id && !message.read_at) {
          await markMessage(message, "read");
        }
      })(),
    );
  }
  await Promise.allSettled(tasks);
}

async function refresh() {
  if (state.refreshing) {
    return;
  }
  state.refreshing = true;
  try {
    await loadClients();
    await loadMessages();
  } finally {
    state.refreshing = false;
  }
}

async function handleEvent(eventName) {
  if (eventName === "clients") {
    await refresh();
  }
  if (eventName === "messages") {
    await loadMessages();
  }
}

async function connectEvents() {
  try {
    const response = await signedFetch("/events");
    if (!response.ok || !response.body) {
      throw new Error("event stream unavailable");
    }
    let buffer = "";
    for await (const chunk of response.body) {
      buffer += decoder.decode(chunk, { stream: true });
      const frames = buffer.split("\n\n");
      buffer = frames.pop();
      for (const frame of frames) {
        const line = frame.split("\n").find((item) => item.startsWith("event: "));
        if (line) {
          await handleEvent(line.slice(7));
        }
      }
    }
  } catch (error) {
    status(error.message, true);
  }
  setTimeout(() => {
    connectEvents();
  }, 2000);
}

function formatDuration(ms) {
  const seconds = Math.ceil(ms / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function formatPlaybackTime(seconds) {
  if (!Number.isFinite(seconds)) {
    return "0:00";
  }
  const whole = Math.floor(seconds);
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, "0")}`;
}

function setPlaybackIcon(button, icon) {
  button.innerHTML = `<svg class="icon"><use href="#icon-${icon}"></use></svg>`;
}

function updateRecordingUi() {
  const recording = state.recording;
  els.recordVoice.hidden = Boolean(recording);
  els.voiceControls.hidden = !recording;
  els.cancelVoice.disabled = Boolean(recording?.stopping);
  els.sendVoice.disabled = Boolean(recording?.stopping);
  els.voiceTimer.textContent = recording
    ? formatDuration(Math.min(Date.now() - recording.startedAt, maxRecordingMs))
    : "0:00";
}

function recordingMimeType() {
  return window.MediaRecorder?.isTypeSupported?.("audio/webm;codecs=opus")
    ? "audio/webm;codecs=opus"
    : "";
}

async function startVoiceRecording() {
  if (!state.selected) {
    status("Select a recipient.", true);
    return;
  }
  if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) {
    status("Voice recording unavailable in this browser.", true);
    return;
  }

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mimeType = recordingMimeType();
    const recorder = new MediaRecorder(
      stream,
      mimeType ? { mimeType } : undefined,
    );
    const recording = {
      recorder,
      chunks: [],
      stream,
      startedAt: Date.now(),
      timer: null,
      send: false,
      stopping: false,
      recipient: state.selected,
      mimeType: mimeType || recorder.mimeType || "audio/webm",
    };
    state.recording = recording;
    recorder.addEventListener("dataavailable", (event) => {
      if (event.data.size > 0) {
        recording.chunks.push(event.data);
      }
    });
    recorder.addEventListener("stop", () => {
      finishVoiceRecording(recording).catch((error) => status(error.message, true));
    });
    recorder.start();
    recording.timer = setInterval(() => {
      updateRecordingUi();
      if (Date.now() - recording.startedAt >= maxRecordingMs) {
        stopVoiceRecording(true);
      }
    }, 250);
    updateRecordingUi();
    status("Recording voice message.");
  } catch (error) {
    stream?.getTracks().forEach((track) => track.stop());
    status(error.message, true);
  }
}

function stopVoiceRecording(send) {
  const recording = state.recording;
  if (!recording) {
    return;
  }
  if (recording.stopping) {
    return;
  }
  recording.stopping = true;
  recording.send = send;
  updateRecordingUi();
  if (recording.recorder.state !== "inactive") {
    recording.recorder.stop();
  }
}

async function finishVoiceRecording(recording) {
  clearInterval(recording.timer);
  recording.stream.getTracks().forEach((track) => track.stop());
  if (state.recording === recording) {
    state.recording = null;
    updateRecordingUi();
  }
  if (!recording.send) {
    status("Voice recording canceled.");
    return;
  }
  const blob = new Blob(recording.chunks, { type: recording.mimeType });
  if (!blob.size) {
    status("No audio captured.", true);
    return;
  }
  await sendVoiceMessage(
    blob,
    Math.min(Date.now() - recording.startedAt, maxRecordingMs),
    recording.recipient,
  );
}

async function encryptFor(recipient, plaintext, metadata = {}) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: await encryptionPublicKey(recipient.encryption_public_key),
    },
    await encryptionPrivateKey(),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    typeof plaintext === "string" ? encoder.encode(plaintext) : plaintext,
  );
  return JSON.stringify({
    v: 1,
    alg: "ECDH-P256+A256GCM",
    ...metadata,
    sender_epk: state.identity.encryptionPublicKey,
    iv: b64(iv),
    data: b64(ciphertext),
  });
}

async function decryptMessage(message) {
  let envelope;
  try {
    envelope = JSON.parse(message.ciphertext);
    const peerKey =
      message.sender_id === state.identity.clientId
        ? state.clients.find((client) => client.id === message.recipient_id)
            ?.encryption_public_key
        : envelope.sender_epk;
    if (!peerKey || envelope.v !== 1) {
      return {
        kind: "error",
        text:
          envelope.kind === "voice"
            ? "[unable to decrypt voice message]"
            : "[unable to decrypt]",
      };
    }
    const key = await crypto.subtle.deriveKey(
      { name: "ECDH", public: await encryptionPublicKey(peerKey) },
      await encryptionPrivateKey(),
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes(envelope.iv) },
      key,
      bytes(envelope.data),
    );
    if (envelope.kind === "voice") {
      return {
        kind: "voice",
        data: plaintext,
        mimeType: envelope.mime_type || "audio/webm",
      };
    }
    return { kind: "text", text: decoder.decode(plaintext) };
  } catch {
    return {
      kind: "error",
      text:
        envelope?.kind === "voice"
          ? "[unable to decrypt voice message]"
          : "[unable to decrypt]",
    };
  }
}

async function sendMessage(event) {
  event.preventDefault();
  if (!state.selected) {
    status("Select a recipient.", true);
    return;
  }
  const text = els.messageText.value.trim();
  if (!text) {
    return;
  }
  const body = JSON.stringify({
    id: crypto.randomUUID(),
    recipient_id: state.selected.id,
    ciphertext: await encryptFor(state.selected, text),
  });
  await apiJson(await signedFetch("/messages", { method: "POST", body }));
  els.messageText.value = "";
  await loadMessages({ scrollToBottom: true });
}

async function sendVoiceMessage(blob, durationMs, recipient) {
  const body = JSON.stringify({
    id: crypto.randomUUID(),
    recipient_id: recipient.id,
    ciphertext: await encryptFor(
      recipient,
      new Uint8Array(await blob.arrayBuffer()),
      {
        kind: "voice",
        mime_type: blob.type || "audio/webm",
        duration_ms: Math.round(durationMs),
      },
    ),
  });
  await apiJson(await signedFetch("/messages", { method: "POST", body }));
  status("Voice message sent.");
  await loadMessages({ scrollToBottom: true });
}

async function renderMessageBody(message) {
  const payload = await decryptMessage(message);
  if (payload.kind === "voice") {
    const url = URL.createObjectURL(
      new Blob([payload.data], { type: payload.mimeType }),
    );
    const player = document.createElement("div");
    const button = document.createElement("button");
    const seek = document.createElement("input");
    const time = document.createElement("span");
    const audio = document.createElement("audio");

    state.audioUrls.push(url);
    player.className = "voice-player";
    button.type = "button";
    button.className = "voice-play";
    button.setAttribute("aria-label", "Play voice message");
    setPlaybackIcon(button, "play");
    seek.type = "range";
    seek.className = "voice-seek";
    seek.min = "0";
    seek.max = "0";
    seek.step = "0.01";
    seek.value = "0";
    seek.setAttribute("aria-label", "Voice message position");
    time.className = "voice-time";
    time.textContent = "0:00";
    audio.hidden = true;
    audio.preload = "metadata";
    audio.src = url;

    audio.addEventListener("loadedmetadata", () => {
      seek.max = String(audio.duration || 0);
      time.textContent = `0:00 / ${formatPlaybackTime(audio.duration)}`;
    });
    audio.addEventListener("timeupdate", () => {
      seek.value = String(audio.currentTime);
      time.textContent = `${formatPlaybackTime(audio.currentTime)} / ${formatPlaybackTime(audio.duration)}`;
    });
    audio.addEventListener("play", () => {
      button.setAttribute("aria-label", "Pause voice message");
      setPlaybackIcon(button, "pause");
    });
    audio.addEventListener("pause", () => {
      button.setAttribute("aria-label", "Play voice message");
      setPlaybackIcon(button, "play");
    });
    audio.addEventListener("ended", () => {
      audio.currentTime = 0;
      seek.value = "0";
    });
    button.addEventListener("click", () => {
      if (audio.paused) {
        audio.play().catch((error) => status(error.message, true));
      } else {
        audio.pause();
      }
    });
    seek.addEventListener("input", () => {
      audio.currentTime = Number(seek.value);
    });

    player.append(button, seek, time, audio);
    return player;
  }
  const text = document.createElement("p");
  text.className = "message-text";
  text.textContent = payload.text;
  return text;
}

async function loadMessages({ scrollToBottom = false } = {}) {
  const scrollFromBottom = els.messages.scrollHeight - els.messages.scrollTop;
  state.messages = await apiJson(await signedFetch("/messages?limit=100"));
  await syncMessageState();
  state.audioUrls.forEach((url) => URL.revokeObjectURL(url));
  state.audioUrls = [];
  els.messages.replaceChildren();
  renderClients();
  if (!state.selected) {
    return;
  }
  for (const message of state.messages) {
    if (state.selected && peerId(message) !== state.selected.id) {
      continue;
    }
    const item = document.createElement("article");
    item.className =
      message.sender_id === state.identity.clientId ? "message own" : "message";
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent =
      message.sender_id === state.identity.clientId
        ? `to ${message.recipient_id} - ${messageState(message)}`
        : `from ${message.sender_id}`;
    item.append(meta, await renderMessageBody(message));
    els.messages.append(item);
  }
  els.messages.scrollTop = scrollToBottom
    ? els.messages.scrollHeight
    : els.messages.scrollHeight - scrollFromBottom;
}

function renderClients() {
  els.clients.replaceChildren();
  for (const client of state.clients) {
    const isSelf = client.id === state.identity?.clientId;
    const node = els.clientTemplate.content.firstElementChild.cloneNode(true);
    node.classList.toggle("active", state.selected?.id === client.id);
    node.classList.toggle("self", isSelf);
    node.querySelector(".client-name").textContent = client.display_name;
    const count = unreadCount(client.id);
    node.querySelector(".client-id").textContent = isSelf ? `${client.id} - you` : client.id;
    if (count > 0) {
      const badge = document.createElement("span");
      badge.className = "unread";
      badge.textContent = String(count);
      node.append(badge);
    }
    node.addEventListener("click", async () => {
      state.selected = client;
      localStorage.setItem(selectedKey, client.id);
      els.chatTitle.textContent = client.display_name;
      renderClients();
      await loadMessages();
    });
    els.clients.append(node);
  }
}

els.refreshClients.addEventListener("click", () => {
  refresh().catch((error) => status(error.message, true));
});
els.openSettings.addEventListener("click", openSettings);
els.closeSettings.addEventListener("click", closeSettings);
els.exportIdentity.addEventListener("click", () => {
  exportIdentity().catch((error) => status(error.message, true));
});
els.resetIdentity.addEventListener("click", resetIdentity);
els.settingsModal.addEventListener("click", (event) => {
  if (event.target === els.settingsModal) {
    closeSettings();
  }
});
els.messageForm.addEventListener("submit", (event) => {
  sendMessage(event).catch((error) => status(error.message, true));
});
els.recordVoice.addEventListener("click", () => {
  startVoiceRecording().catch((error) => status(error.message, true));
});
els.cancelVoice.addEventListener("click", () => {
  stopVoiceRecording(false);
});
els.sendVoice.addEventListener("click", () => {
  stopVoiceRecording(true);
});

if (savedIdentity) {
  loadIdentity();
  connectEvents();
}
