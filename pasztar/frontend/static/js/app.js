const storeKey = "pasztar.identity";
const pendingKey = "pasztar.pendingIdentity";
const selectedKey = "pasztar.selectedClient";
const maxRecordingMs = 60000;
const maxAttachmentBytes = 100 * 1024 * 1024;
const maxImageDimension = 1600;
const eventReconnectBaseMs = 2000;
const eventReconnectMaxMs = 30000;
const callHeartbeatMs = 10000;
const callSignalPollMs = 2000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  identity: null,
  clients: [],
  messages: [],
  selected: null,
  refreshing: false,
  loadingMessages: false,
  pendingMessageLoad: null,
  eventsConnecting: false,
  eventReconnectMs: eventReconnectBaseMs,
  marking: new Set(),
  recording: null,
  audioContext: null,
  voiceStops: new Set(),
  contextMenu: null,
  selectedMessageIds: new Set(),
  replyTarget: null,
  forwardingMessages: [],
  forwardingSending: false,
  calls: [],
  declinedCallIds: new Set(),
  activeCall: null,
  activeCallPeerId: null,
  callStarting: false,
  callMuted: false,
  callCameraOff: true,
  callPeerMuted: false,
  callPeerCameraOff: true,
  callCollapsedManual: false,
  callStream: null,
  remoteStream: null,
  peerConnection: null,
  callSignalsSeen: new Set(),
  callPendingCandidates: [],
  callHeartbeat: null,
  callSignalPoll: null,
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
  chat: document.querySelector(".chat"),
  startCall: document.querySelector("#start-call"),
  callPanel: document.querySelector("#call-panel"),
  callStatus: document.querySelector("#call-status"),
  callFlags: document.querySelector("#call-flags"),
  remoteVideo: document.querySelector("#remote-video"),
  localVideo: document.querySelector("#local-video"),
  remotePlaceholder: document.querySelector("#remote-placeholder"),
  remoteMuted: document.querySelector("#remote-muted"),
  localMuted: document.querySelector("#local-muted"),
  acceptCall: document.querySelector("#accept-call"),
  declineCall: document.querySelector("#decline-call"),
  muteCall: document.querySelector("#mute-call"),
  cameraCall: document.querySelector("#camera-call"),
  toggleCallSize: document.querySelector("#toggle-call-size"),
  leaveCall: document.querySelector("#leave-call"),
  messages: document.querySelector("#messages"),
  exportIdentity: document.querySelector("#export-identity"),
  resetIdentity: document.querySelector("#reset-identity"),
  messageForm: document.querySelector("#message-form"),
  messageText: document.querySelector("#message-text"),
  sendText: document.querySelector("#send-text"),
  openAttachments: document.querySelector("#open-attachments"),
  attachmentMenu: document.querySelector("#attachment-menu"),
  recordVoice: document.querySelector("#record-voice"),
  pickImage: document.querySelector("#pick-image"),
  pickFile: document.querySelector("#pick-file"),
  imageInput: document.querySelector("#image-input"),
  fileInput: document.querySelector("#file-input"),
  voiceControls: document.querySelector("#voice-controls"),
  voiceTimer: document.querySelector("#voice-timer"),
  cancelVoice: document.querySelector("#cancel-voice"),
  sendVoice: document.querySelector("#send-voice"),
  replyPreview: document.querySelector("#reply-preview"),
  replyPreviewText: document.querySelector("#reply-preview-text"),
  cancelReply: document.querySelector("#cancel-reply"),
  clientsPanel: document.querySelector(".clients-panel"),
  forwardingBar: document.querySelector("#forwarding-bar"),
  forwardingCount: document.querySelector("#forwarding-count"),
  cancelForwarding: document.querySelector("#cancel-forwarding"),
  selectionBar: document.querySelector("#selection-bar"),
  selectionCount: document.querySelector("#selection-count"),
  cancelSelection: document.querySelector("#cancel-selection"),
  deleteSelected: document.querySelector("#delete-selected"),
  forwardSelected: document.querySelector("#forward-selected"),
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

function truncateText(value, length = 92) {
  return value.length > length ? `${value.slice(0, length - 1)}...` : value;
}

function displayNameForId(clientId) {
  if (clientId === state.identity.clientId) {
    return "You";
  }
  return (
    state.clients.find((client) => client.id === clientId)?.display_name ||
    clientId
  );
}

function messageAuthor(message) {
  return displayNameForId(message.sender_id);
}

async function messageSummary(message) {
  const payload = await decryptMessage(message);
  if (payload.kind === "voice") {
    return "Voice message";
  }
  if (payload.kind === "image") {
    return `Image: ${payload.name}`;
  }
  if (payload.kind === "file") {
    return `File: ${payload.name}`;
  }
  if (payload.kind === "call_event") {
    return `Call ${payload.event}`;
  }
  return truncateText(payload.text || "[unable to decrypt]");
}

function clearReplyTarget() {
  state.replyTarget = null;
  els.replyPreview.hidden = true;
  els.replyPreviewText.textContent = "";
}

async function updateReplyUi() {
  const target = state.replyTarget;
  if (!target) {
    clearReplyTarget();
    return;
  }
  els.replyPreview.hidden = false;
  els.replyPreviewText.textContent = `${messageAuthor(target)}: ${await messageSummary(
    target,
  )}`;
}

async function setReplyTarget(message) {
  if (state.selectedMessageIds.size > 0) {
    state.selectedMessageIds.clear();
    updateSelectionUi();
  }
  state.replyTarget = message;
  await updateReplyUi();
  els.messageText.focus();
}

function closeContextMenu() {
  state.contextMenu?.remove();
  state.contextMenu = null;
}

function setAttachmentMenu(open) {
  els.attachmentMenu.hidden = !open;
  els.messageForm.classList.toggle("attachments-open", open);
  els.openAttachments.setAttribute("aria-expanded", String(open));
}

function closeAttachmentMenu() {
  setAttachmentMenu(false);
}

function updateSelectionUi() {
  const count = state.selectedMessageIds.size;
  const forwarding = state.forwardingMessages.length > 0;
  els.messageForm.hidden = count > 0 || forwarding;
  els.selectionBar.hidden = count === 0 || forwarding;
  els.forwardingBar.hidden = !forwarding;
  els.selectionCount.textContent = `${count} selected`;
  els.deleteSelected.disabled = count === 0;
  els.forwardSelected.disabled = count === 0;
  els.forwardingCount.textContent = forwarding
    ? `Forwarding ${state.forwardingMessages.length} message${
        state.forwardingMessages.length === 1 ? "" : "s"
      } - select a recipient from the client list`
    : "";
  els.chat.classList.toggle("forwarding", forwarding);
  els.clientsPanel.classList.toggle("forwarding", forwarding);
  els.cancelForwarding.disabled = state.forwardingSending;
}

function exitSelection() {
  state.selectedMessageIds.clear();
  updateSelectionUi();
  renderMessagesFromState().catch((error) => status(error.message, true));
}

function toggleMessageSelection(message) {
  if (state.selectedMessageIds.has(message.id)) {
    state.selectedMessageIds.delete(message.id);
  } else {
    state.selectedMessageIds.add(message.id);
  }
  updateSelectionUi();
  renderMessagesFromState().catch((error) => status(error.message, true));
}

function enterSelection(message) {
  if (state.recording) {
    stopVoiceRecording(false);
  }
  clearReplyTarget();
  state.selectedMessageIds.add(message.id);
  updateSelectionUi();
  renderMessagesFromState().catch((error) => status(error.message, true));
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
    state.selected =
      state.clients.find((client) => client.id === selectedId) || null;
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
  updateCallUi();
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

function messageDate(message) {
  return new Date(message.created_at);
}

function dayKey(date) {
  return [
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, "0"),
    String(date.getDate()).padStart(2, "0"),
  ].join("-");
}

function formatMessageDay(date) {
  return new Intl.DateTimeFormat(undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
  }).format(date);
}

function formatMessageTime(date) {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function callPeerId(call) {
  if (!call) {
    return null;
  }
  return call.client_a_id === state.identity.clientId
    ? call.client_b_id
    : call.client_a_id;
}

function visibleCallForSelected() {
  if (!state.selected) {
    return null;
  }
  return (
    state.calls.find(
      (call) =>
        !call.ended_at &&
        callPeerId(call) === state.selected.id &&
        !state.declinedCallIds.has(call.id),
    ) || null
  );
}

function callHasPeer(call) {
  return Boolean(
    call &&
    state.activeCallPeerId &&
    call.participants.includes(state.identity.clientId) &&
    call.participants.includes(state.activeCallPeerId),
  );
}

function isCallOfferer() {
  return (
    state.activeCallPeerId &&
    state.identity.clientId.localeCompare(state.activeCallPeerId) < 0
  );
}

function setButtonIcon(button, icon) {
  button.innerHTML = `<svg class="icon"><use href="#icon-${icon}"></use></svg>`;
}

function updateCallButtons() {
  els.startCall.disabled =
    !state.selected ||
    state.selected.id === state.identity.clientId ||
    state.callStarting;
  setButtonIcon(els.muteCall, state.callMuted ? "mic" : "mic");
  setButtonIcon(els.cameraCall, state.callCameraOff ? "video-off" : "video");
  els.muteCall.classList.toggle("active", state.callMuted);
  els.cameraCall.classList.toggle("active", state.callCameraOff);
  els.muteCall.title = state.callMuted
    ? "Unmute microphone"
    : "Mute microphone";
  els.cameraCall.title = state.callCameraOff
    ? "Turn camera on"
    : "Turn camera off";
  els.muteCall.setAttribute("aria-label", els.muteCall.title);
  els.cameraCall.setAttribute("aria-label", els.cameraCall.title);
}

function updateCallUi() {
  updateCallButtons();
  const incoming = state.activeCall ? null : visibleCallForSelected();
  const active = state.activeCall;
  const allCamerasOff =
    Boolean(active) && state.callCameraOff && state.callPeerCameraOff;
  const compact =
    Boolean(active) && (state.callCollapsedManual || allCamerasOff);
  const peerName = active ? displayNameForId(state.activeCallPeerId) : "";
  els.callPanel.hidden = !incoming && !active;
  els.acceptCall.hidden = !incoming;
  els.declineCall.hidden = !incoming;
  els.muteCall.hidden = !active;
  els.cameraCall.hidden = !active;
  els.toggleCallSize.hidden =
    !active || (allCamerasOff && !state.callCollapsedManual);
  els.leaveCall.hidden = !active;
  els.callPanel.classList.toggle("active-call", Boolean(active));
  els.callPanel.classList.toggle("compact-call", compact);
  els.chat.classList.toggle("call-expanded", Boolean(active) && !compact);
  els.remotePlaceholder.textContent = peerName;
  els.remotePlaceholder.hidden = !active || !state.callPeerCameraOff || compact;
  els.localVideo.hidden = !active || state.callCameraOff || compact;
  els.remoteMuted.hidden = !active || !state.callPeerMuted || compact;
  els.localMuted.hidden = !active || !state.callMuted || compact;
  setButtonIcon(els.toggleCallSize, compact ? "maximize" : "minimize");
  els.toggleCallSize.title = compact ? "Expand call" : "Shrink call";
  els.toggleCallSize.setAttribute("aria-label", els.toggleCallSize.title);
  if (active) {
    els.callStatus.textContent = callHasPeer(active)
      ? `In call with ${peerName}`
      : `Waiting for ${peerName}`;
    els.callFlags.textContent = [
      state.callMuted ? "You muted" : "",
      state.callPeerMuted ? `${peerName} muted` : "",
      state.callCameraOff ? "Your camera off" : "",
      state.callPeerCameraOff ? `${peerName} camera off` : "",
    ]
      .filter(Boolean)
      .join(" - ");
    return;
  }
  if (incoming) {
    els.callStatus.textContent = `${displayNameForId(callPeerId(incoming))} is calling`;
    els.callFlags.textContent = "";
  }
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
    await loadCalls();
  } finally {
    state.refreshing = false;
  }
}

async function handleEvent(eventName) {
  if (eventName === "ready") {
    state.eventReconnectMs = eventReconnectBaseMs;
    status("Event stream connected.");
  }
  if (eventName === "clients") {
    await refresh();
  }
  if (eventName === "messages") {
    await loadMessages();
  }
  if (eventName === "calls") {
    await loadCalls();
  }
}

async function connectEvents() {
  if (state.eventsConnecting) {
    return;
  }
  state.eventsConnecting = true;
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
        const line = frame
          .split("\n")
          .find((item) => item.startsWith("event: "));
        if (line) {
          await handleEvent(line.slice(7));
        }
      }
    }
    throw new Error("event stream closed");
  } catch (error) {
    status(`${error.message}; reconnecting.`, true);
  } finally {
    state.eventsConnecting = false;
  }
  const delay = state.eventReconnectMs;
  state.eventReconnectMs = Math.min(
    state.eventReconnectMs * 2,
    eventReconnectMaxMs,
  );
  setTimeout(() => {
    connectEvents();
  }, delay);
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

function playbackContext() {
  state.audioContext =
    state.audioContext ||
    new (window.AudioContext || window.webkitAudioContext)();
  return state.audioContext;
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

function resizeMessageText() {
  els.messageText.style.height = "46px";
  els.messageText.style.height = `${Math.min(
    els.messageText.scrollHeight,
    160,
  )}px`;
}

function recordingMimeType() {
  return window.MediaRecorder?.isTypeSupported?.("audio/webm;codecs=opus")
    ? "audio/webm;codecs=opus"
    : "";
}

async function startVoiceRecording() {
  closeAttachmentMenu();
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
      finishVoiceRecording(recording).catch((error) =>
        status(error.message, true),
      );
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

function attachmentName(name, fallback) {
  const trimmed = (name || "").trim();
  return trimmed || fallback;
}

function compressedImageName(name) {
  return attachmentName(name, "image.jpg").replace(/\.[^.]*$/, "") + ".jpg";
}

async function compressImage(file) {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(
    1,
    maxImageDimension / Math.max(bitmap.width, bitmap.height),
  );
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(bitmap.width * scale));
  canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  const context = canvas.getContext("2d");
  context.fillStyle = "#fff";
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close?.();
  const blob = await new Promise((resolve) =>
    canvas.toBlob(resolve, "image/jpeg", 0.82),
  );
  if (!blob) {
    throw new Error("Could not compress image.");
  }
  return {
    blob,
    name: compressedImageName(file.name),
    mimeType: "image/jpeg",
  };
}

async function prepareAttachment(file, kind) {
  if (kind === "image") {
    return compressImage(file);
  }
  return {
    blob: file,
    name: attachmentName(file.name, "attachment"),
    mimeType: file.type || "application/octet-stream",
  };
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
        forwardedFrom: envelope.forwarded_from || null,
        text: `[unable to decrypt ${envelope.kind || "message"}]`,
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
        forwardedFrom: envelope.forwarded_from || null,
        data: plaintext,
        durationMs: Number(envelope.duration_ms) || 0,
        mimeType: envelope.mime_type || "audio/webm",
      };
    }
    if (envelope.kind === "image" || envelope.kind === "file") {
      return {
        kind: envelope.kind,
        forwardedFrom: envelope.forwarded_from || null,
        data: plaintext,
        name: attachmentName(envelope.name, envelope.kind),
        mimeType: envelope.mime_type || "application/octet-stream",
      };
    }
    if (envelope.kind === "call_event") {
      return {
        kind: "call_event",
        forwardedFrom: envelope.forwarded_from || null,
        event: envelope.event || "started",
      };
    }
    return {
      kind: "text",
      forwardedFrom: envelope.forwarded_from || null,
      text: decoder.decode(plaintext),
    };
  } catch {
    return {
      kind: "error",
      forwardedFrom: envelope?.forwarded_from || null,
      text: `[unable to decrypt ${envelope?.kind || "message"}]`,
    };
  }
}

async function postEncryptedMessage(
  recipient,
  plaintext,
  metadata = {},
  clearReply = true,
) {
  if (!recipient) {
    throw new Error("Select a recipient.");
  }
  const payload = {
    id: crypto.randomUUID(),
    recipient_id: recipient.id,
    ciphertext: await encryptFor(recipient, plaintext, metadata),
  };
  if (state.replyTarget && peerId(state.replyTarget) === recipient.id) {
    payload.reply_to_id = state.replyTarget.id;
  }
  const body = JSON.stringify(payload);
  await apiJson(await signedFetch("/messages", { method: "POST", body }));
  if (clearReply) {
    clearReplyTarget();
  }
}

async function sendMessage(event) {
  event.preventDefault();
  const text = els.messageText.value.trim();
  if (!text) {
    return;
  }
  await postEncryptedMessage(state.selected, text);
  els.messageText.value = "";
  resizeMessageText();
  await loadMessages({ scrollToBottom: true });
}

async function sendVoiceMessage(blob, durationMs, recipient) {
  await postEncryptedMessage(
    recipient,
    new Uint8Array(await blob.arrayBuffer()),
    {
      kind: "voice",
      mime_type: blob.type || "audio/webm",
      duration_ms: Math.round(durationMs),
    },
  );
  status("Voice message sent.");
  await loadMessages({ scrollToBottom: true });
}

async function sendAttachment(file, kind) {
  const recipient = state.selected;
  if (!recipient) {
    status("Select a recipient.", true);
    return;
  }
  const attachment = await prepareAttachment(file, kind);
  if (attachment.blob.size > maxAttachmentBytes) {
    throw new Error("Attachment is too large.");
  }
  await postEncryptedMessage(
    recipient,
    new Uint8Array(await attachment.blob.arrayBuffer()),
    {
      kind,
      name: attachment.name,
      mime_type: attachment.mimeType,
    },
  );
  status(`${kind === "image" ? "Image" : "File"} sent.`);
  await loadMessages({ scrollToBottom: true });
}

async function sendCallEventMessage(eventName, recipient) {
  if (!recipient) {
    return;
  }
  await postEncryptedMessage(
    recipient,
    eventName,
    { kind: "call_event", event: eventName },
    false,
  );
  await loadMessages({ scrollToBottom: true });
}

function callPeerClient() {
  return state.clients.find((client) => client.id === state.activeCallPeerId);
}

function closePeerConnection() {
  state.peerConnection?.close();
  state.peerConnection = null;
  state.remoteStream = null;
  state.callPendingCandidates = [];
  els.remoteVideo.srcObject = null;
}

function stopCallMedia() {
  state.callStream?.getTracks().forEach((track) => track.stop());
  state.callStream = null;
  els.localVideo.srcObject = null;
}

function clearCallTimers() {
  clearInterval(state.callHeartbeat);
  clearInterval(state.callSignalPoll);
  state.callHeartbeat = null;
  state.callSignalPoll = null;
}

function cleanupLocalCall() {
  clearCallTimers();
  closePeerConnection();
  stopCallMedia();
  state.activeCall = null;
  state.activeCallPeerId = null;
  state.callSignalsSeen.clear();
  state.callMuted = false;
  state.callCameraOff = true;
  state.callPeerMuted = false;
  state.callPeerCameraOff = true;
  state.callCollapsedManual = false;
  updateCallUi();
}

async function ensureCallMedia() {
  if (state.callStream) {
    return;
  }
  if (state.recording) {
    stopVoiceRecording(false);
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("Calls unavailable in this browser.");
  }
  state.callStream = await navigator.mediaDevices.getUserMedia({
    audio: true,
    video: false,
  });
  els.localVideo.srcObject = state.callStream;
}

function applyCallTrackState() {
  state.callStream
    ?.getAudioTracks()
    .forEach((track) => (track.enabled = !state.callMuted));
  state.callStream
    ?.getVideoTracks()
    .forEach((track) => (track.enabled = !state.callCameraOff));
  updateCallButtons();
  updateCallUi();
}

async function enableCamera() {
  if (!state.callStream || !navigator.mediaDevices?.getUserMedia) {
    return;
  }
  if (state.callStream.getVideoTracks().length === 0) {
    const videoStream = await navigator.mediaDevices.getUserMedia({
      video: true,
    });
    const track = videoStream.getVideoTracks()[0];
    state.callStream.addTrack(track);
    if (state.peerConnection) {
      state.peerConnection.addTrack(track, state.callStream);
    }
  }
  state.callCameraOff = false;
  els.localVideo.srcObject = state.callStream;
  applyCallTrackState();
  await sendCallState();
  await sendOffer(true);
}

async function disableCamera() {
  for (const track of state.callStream?.getVideoTracks() || []) {
    for (const sender of state.peerConnection?.getSenders() || []) {
      if (sender.track === track) {
        state.peerConnection.removeTrack(sender);
      }
    }
    state.callStream.removeTrack(track);
    track.stop();
  }
  state.callCameraOff = true;
  els.localVideo.srcObject = state.callStream;
  applyCallTrackState();
  await sendCallState();
  await sendOffer(true);
}

async function sendCallSignal(type, data) {
  const recipient = callPeerClient();
  if (!state.activeCall || !recipient) {
    return;
  }
  const body = JSON.stringify({
    id: crypto.randomUUID(),
    recipient_id: recipient.id,
    ciphertext: await encryptFor(recipient, JSON.stringify({ type, data }), {
      kind: "call_signal",
    }),
  });
  await apiJson(
    await signedFetch(
      `/calls/${encodeURIComponent(state.activeCall.id)}/signals`,
      {
        method: "POST",
        body,
      },
    ),
  );
}

async function sendCallState() {
  await sendCallSignal("state", {
    muted: state.callMuted,
    cameraOff: state.callCameraOff,
  }).catch(() => null);
}

async function flushPendingCandidates() {
  const pending = state.callPendingCandidates.splice(0);
  for (const candidate of pending) {
    await state.peerConnection?.addIceCandidate(candidate);
  }
}

function createPeerConnection() {
  closePeerConnection();
  const pc = new RTCPeerConnection({ iceServers: [] });
  const remote = new MediaStream();
  state.peerConnection = pc;
  state.remoteStream = remote;
  els.remoteVideo.srcObject = remote;
  for (const track of state.callStream?.getTracks() || []) {
    pc.addTrack(track, state.callStream);
  }
  pc.addEventListener("track", (event) => {
    for (const track of event.streams[0]?.getTracks() || [event.track]) {
      remote.addTrack(track);
    }
  });
  pc.addEventListener("icecandidate", (event) => {
    if (event.candidate) {
      sendCallSignal("candidate", event.candidate.toJSON()).catch((error) =>
        status(error.message, true),
      );
    }
  });
  pc.addEventListener("connectionstatechange", () => {
    if (pc.connectionState === "failed") {
      status("Call connection failed.", true);
    }
  });
  return pc;
}

async function sendOffer(force = false) {
  if (!callHasPeer(state.activeCall)) {
    return;
  }
  const pc = state.peerConnection || createPeerConnection();
  if (pc.signalingState !== "stable" || (!force && pc.localDescription)) {
    return;
  }
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await sendCallSignal("offer", pc.localDescription);
}

async function ensurePeerConnectionState() {
  if (!state.activeCall || !state.callStream) {
    return;
  }
  if (!callHasPeer(state.activeCall)) {
    closePeerConnection();
    return;
  }
  if (
    state.peerConnection &&
    ["closed", "disconnected", "failed"].includes(
      state.peerConnection.connectionState,
    )
  ) {
    closePeerConnection();
  }
  if (!state.peerConnection) {
    createPeerConnection();
  }
  if (isCallOfferer()) {
    await sendOffer();
  }
}

async function handleCallSignal(signal) {
  if (signal.sender_id !== state.activeCallPeerId) {
    return;
  }
  const payload = await decryptMessage({
    ciphertext: signal.ciphertext,
    sender_id: signal.sender_id,
    recipient_id: signal.recipient_id,
  });
  if (payload.kind !== "text") {
    throw new Error("Cannot decrypt call signal.");
  }
  const { type, data } = JSON.parse(payload.text);
  if (type === "state") {
    state.callPeerMuted = Boolean(data?.muted);
    state.callPeerCameraOff = data?.cameraOff !== false;
    updateCallUi();
    return;
  }
  const pc = state.peerConnection || createPeerConnection();
  if (type === "offer") {
    await pc.setRemoteDescription(data);
    await flushPendingCandidates();
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await sendCallSignal("answer", pc.localDescription);
    return;
  }
  if (type === "answer") {
    if (pc.signalingState !== "stable") {
      await pc.setRemoteDescription(data);
      await flushPendingCandidates();
    }
    return;
  }
  if (type === "candidate") {
    const candidate = new RTCIceCandidate(data);
    if (pc.remoteDescription) {
      await pc.addIceCandidate(candidate);
    } else {
      state.callPendingCandidates.push(candidate);
    }
  }
}

async function pollCallSignals() {
  if (!state.activeCall) {
    return;
  }
  const signals = await apiJson(
    await signedFetch(
      `/calls/${encodeURIComponent(state.activeCall.id)}/signals`,
    ),
  );
  for (const signal of signals) {
    if (state.callSignalsSeen.has(signal.id)) {
      continue;
    }
    state.callSignalsSeen.add(signal.id);
    await handleCallSignal(signal);
  }
}

function startCallTimers() {
  clearCallTimers();
  state.callHeartbeat = setInterval(() => {
    if (!state.activeCall) {
      return;
    }
    signedFetch(`/calls/${encodeURIComponent(state.activeCall.id)}/heartbeat`, {
      method: "POST",
    })
      .then(apiJson)
      .then((call) => {
        state.activeCall = call;
        updateCallUi();
      })
      .catch((error) => {
        cleanupLocalCall();
        status(error.message, true);
      });
  }, callHeartbeatMs);
  state.callSignalPoll = setInterval(() => {
    pollCallSignals().catch((error) => status(error.message, true));
  }, callSignalPollMs);
}

async function enterCall(call) {
  if (state.activeCall && state.activeCall.id !== call.id) {
    await leaveCall(true);
  }
  state.declinedCallIds.delete(call.id);
  state.activeCall = call;
  state.activeCallPeerId = callPeerId(call);
  state.callSignalsSeen.clear();
  state.callPendingCandidates = [];
  state.callMuted = false;
  state.callCameraOff = false;
  try {
    await ensureCallMedia();
  } catch (error) {
    cleanupLocalCall();
    try {
      await apiJson(
        await signedFetch(`/calls/${encodeURIComponent(call.id)}/leave`, {
          method: "POST",
        }),
      );
    } catch {
      // The local permission failure is the useful error to surface.
    }
    throw error;
  }
  applyCallTrackState();
  await sendCallState();
  startCallTimers();
  updateCallUi();
  await ensurePeerConnectionState();
  await pollCallSignals();
}

async function loadCalls() {
  state.calls = await apiJson(await signedFetch("/calls"));
  if (state.activeCall) {
    const hadPeer = callHasPeer(state.activeCall);
    const active = state.calls.find((call) => call.id === state.activeCall.id);
    if (!active || !active.participants.includes(state.identity.clientId)) {
      cleanupLocalCall();
    } else {
      state.activeCall = active;
      await ensurePeerConnectionState();
      const hasPeer = callHasPeer(active);
      if (!hadPeer && hasPeer) {
        await sendCallState();
      }
      await pollCallSignals();
    }
  }
  updateCallUi();
}

async function startCall() {
  if (!state.selected || state.selected.id === state.identity.clientId) {
    status("Select another client.", true);
    return;
  }
  const recipient = state.selected;
  state.callStarting = true;
  updateCallButtons();
  try {
    if (state.activeCall) {
      await leaveCall(true);
    }
    const body = JSON.stringify({ recipient_id: recipient.id });
    const call = await apiJson(
      await signedFetch("/calls", { method: "POST", body }),
    );
    await enterCall(call);
    await sendCallEventMessage("started", recipient);
    status("Call started.");
  } finally {
    state.callStarting = false;
    updateCallButtons();
  }
}

async function acceptCall() {
  const call = visibleCallForSelected();
  if (!call) {
    return;
  }
  if (state.activeCall) {
    await leaveCall(true);
  }
  const joined = await apiJson(
    await signedFetch(`/calls/${encodeURIComponent(call.id)}/join`, {
      method: "POST",
    }),
  );
  await enterCall(joined);
}

function declineCall() {
  const call = visibleCallForSelected();
  if (call) {
    state.declinedCallIds.add(call.id);
  }
  updateCallUi();
}

async function leaveCall(notify = true) {
  const call = state.activeCall;
  const recipient = callPeerClient();
  cleanupLocalCall();
  if (notify && call) {
    await sendCallEventMessage("ended", recipient);
    await apiJson(
      await signedFetch(`/calls/${encodeURIComponent(call.id)}/leave`, {
        method: "POST",
      }),
    );
    await loadCalls();
  }
}

async function deleteMessageId(messageId) {
  await apiJson(
    await signedFetch(`/messages/${encodeURIComponent(messageId)}`, {
      method: "DELETE",
    }),
  );
}

async function runLimited(items, limit, task) {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const item = items[next];
        next += 1;
        await task(item);
      }
    }),
  );
}

async function deleteMessage(message) {
  if (!confirm("Delete this message for both sides?")) {
    return;
  }
  await deleteMessageId(message.id);
  status("Message deleted.");
  await loadMessages();
}

async function deleteSelectedMessages() {
  const ids = [...state.selectedMessageIds];
  if (
    !ids.length ||
    !confirm(`Delete ${ids.length} selected messages for both sides?`)
  ) {
    return;
  }
  await runLimited(ids, 8, deleteMessageId);
  state.selectedMessageIds.clear();
  updateSelectionUi();
  status(`${ids.length} messages deleted.`);
  await loadMessages();
}

function cancelForwarding() {
  if (state.forwardingSending) {
    return;
  }
  state.forwardingMessages = [];
  updateSelectionUi();
  renderClients();
}

function beginForwarding(messages) {
  if (!messages.length) {
    return;
  }
  if (state.recording) {
    stopVoiceRecording(false);
  }
  clearReplyTarget();
  state.selectedMessageIds.clear();
  state.forwardingMessages = messages;
  updateSelectionUi();
  renderClients();
  renderMessagesFromState().catch((error) => status(error.message, true));
}

async function encryptForwardedMessage(message, recipient) {
  const payload = await decryptMessage(message);
  const forwardedFrom = payload.forwardedFrom || message.sender_id;
  if (payload.kind === "voice") {
    return encryptFor(recipient, new Uint8Array(payload.data), {
      kind: "voice",
      forwarded_from: forwardedFrom,
      mime_type: payload.mimeType,
      duration_ms: Math.round(payload.durationMs),
    });
  }
  if (payload.kind === "image" || payload.kind === "file") {
    return encryptFor(recipient, new Uint8Array(payload.data), {
      kind: payload.kind,
      forwarded_from: forwardedFrom,
      name: payload.name,
      mime_type: payload.mimeType,
    });
  }
  if (payload.kind === "text") {
    return encryptFor(recipient, payload.text, {
      forwarded_from: forwardedFrom,
    });
  }
  if (payload.kind === "call_event") {
    return encryptFor(recipient, payload.event, {
      kind: "call_event",
      forwarded_from: forwardedFrom,
      event: payload.event,
    });
  }
  throw new Error("Cannot forward a message that failed to decrypt.");
}

function downloadAttachment(payload) {
  const blob = new Blob([payload.data], { type: payload.mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = payload.name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function iconNode(icon) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  svg.classList.add("icon");
  use.setAttribute("href", `#icon-${icon}`);
  svg.append(use);
  return svg;
}

async function forwardMessagesTo(recipient) {
  if (state.forwardingSending || state.forwardingMessages.length === 0) {
    return;
  }
  if (recipient.id === state.identity.clientId) {
    status("Pick another client to forward to.", true);
    return;
  }
  state.forwardingSending = true;
  updateSelectionUi();
  try {
    for (const message of state.forwardingMessages) {
      const body = JSON.stringify({
        id: crypto.randomUUID(),
        recipient_id: recipient.id,
        ciphertext: await encryptForwardedMessage(message, recipient),
      });
      await apiJson(await signedFetch("/messages", { method: "POST", body }));
    }
    const count = state.forwardingMessages.length;
    state.forwardingMessages = [];
    state.selected = recipient;
    localStorage.setItem(selectedKey, recipient.id);
    els.chatTitle.textContent = recipient.display_name;
    status(`${count} message${count === 1 ? "" : "s"} forwarded.`);
    updateSelectionUi();
    renderClients();
    await loadMessages({ scrollToBottom: true });
  } finally {
    state.forwardingSending = false;
    updateSelectionUi();
  }
}

function showMessageMenu(event, message) {
  event.preventDefault();
  closeContextMenu();
  const menu = document.createElement("div");
  const replyButton = document.createElement("button");
  const forwardButton = document.createElement("button");
  const selectButton = document.createElement("button");
  const deleteButton = document.createElement("button");
  menu.className = "context-menu";
  replyButton.type = "button";
  replyButton.className = "context-menu-item";
  replyButton.innerHTML =
    '<svg class="icon"><use href="#icon-reply"></use></svg>Reply';
  replyButton.addEventListener("click", () => {
    closeContextMenu();
    setReplyTarget(message).catch((error) => status(error.message, true));
  });
  forwardButton.type = "button";
  forwardButton.className = "context-menu-item";
  forwardButton.innerHTML =
    '<svg class="icon"><use href="#icon-forward"></use></svg>Forward';
  forwardButton.addEventListener("click", () => {
    closeContextMenu();
    beginForwarding([message]);
  });
  selectButton.type = "button";
  selectButton.className = "context-menu-item";
  selectButton.innerHTML =
    '<svg class="icon"><use href="#icon-select"></use></svg>Select';
  selectButton.addEventListener("click", () => {
    closeContextMenu();
    enterSelection(message);
  });
  deleteButton.type = "button";
  deleteButton.className = "context-menu-item danger-item";
  deleteButton.innerHTML =
    '<svg class="icon"><use href="#icon-trash"></use></svg>Delete';
  deleteButton.addEventListener("click", () => {
    closeContextMenu();
    deleteMessage(message).catch((error) => status(error.message, true));
  });
  menu.append(replyButton, forwardButton, selectButton, deleteButton);
  document.body.append(menu);
  state.contextMenu = menu;
  const rect = menu.getBoundingClientRect();
  menu.style.left = `${Math.min(event.clientX, innerWidth - rect.width - 8)}px`;
  menu.style.top = `${Math.min(event.clientY, innerHeight - rect.height - 8)}px`;
}

function scrollToMessage(messageId) {
  const node = [...els.messages.children].find(
    (item) => item.dataset.messageId === messageId,
  );
  node?.scrollIntoView({ block: "center", behavior: "smooth" });
}

async function renderReplyQuote(replyToId) {
  const original = state.messages.find((message) => message.id === replyToId);
  const quote = document.createElement("button");
  const label = document.createElement("span");
  const text = document.createElement("span");
  quote.type = "button";
  quote.className = "reply-quote";
  label.className = "reply-label";
  label.textContent = original
    ? `Reply to ${messageAuthor(original)}`
    : "Reply";
  text.className = "reply-quote-text";
  text.textContent = original
    ? await messageSummary(original)
    : "Original message unavailable";
  if (original) {
    quote.addEventListener("click", (event) => {
      event.stopPropagation();
      scrollToMessage(original.id);
    });
  }
  quote.append(label, text);
  return quote;
}

async function renderForwardedFrom(message) {
  const payload = await decryptMessage(message);
  if (!payload.forwardedFrom) {
    return null;
  }
  const forwarded = document.createElement("p");
  forwarded.className = "forwarded-from";
  forwarded.textContent = `Forwarded from ${displayNameForId(payload.forwardedFrom)}`;
  return forwarded;
}

async function renderMessageBody(message) {
  const payload = await decryptMessage(message);
  if (payload.kind === "call_event") {
    const text = document.createElement("p");
    text.className = "call-event-message";
    text.textContent = `${formatMessageTime(messageDate(message))} call ${payload.event}`;
    return text;
  }
  if (payload.kind === "image") {
    const wrapper = document.createElement("div");
    const image = document.createElement("img");
    const button = document.createElement("button");
    const blob = new Blob([payload.data], { type: payload.mimeType });
    const url = URL.createObjectURL(blob);
    wrapper.className = "image-attachment";
    image.src = url;
    image.alt = payload.name;
    button.type = "button";
    button.className = "attachment-download";
    const name = document.createElement("span");
    name.textContent = payload.name;
    button.append(iconNode("download"), name);
    button.addEventListener("click", () => downloadAttachment(payload));
    state.voiceStops.add(() => URL.revokeObjectURL(url));
    wrapper.append(image, button);
    return wrapper;
  }
  if (payload.kind === "file") {
    const button = document.createElement("button");
    const name = document.createElement("span");
    button.type = "button";
    button.className = "file-attachment";
    name.textContent = payload.name;
    button.append(iconNode("file"), name, iconNode("download"));
    button.addEventListener("click", () => downloadAttachment(payload));
    return button;
  }
  if (payload.kind === "voice") {
    let buffer;
    try {
      buffer = await playbackContext().decodeAudioData(payload.data.slice(0));
    } catch {
      const text = document.createElement("p");
      text.className = "message-text";
      text.textContent = "[unable to play voice message]";
      return text;
    }
    const duration = buffer.duration || payload.durationMs / 1000;
    const player = document.createElement("div");
    const button = document.createElement("button");
    const rewind = document.createElement("button");
    const forward = document.createElement("button");
    const seek = document.createElement("input");
    const time = document.createElement("span");
    let source = null;
    let startedAt = 0;
    let offset = 0;
    let frame = 0;

    player.className = "voice-player";
    button.type = "button";
    button.className = "voice-play";
    button.setAttribute("aria-label", "Play voice message");
    setPlaybackIcon(button, "play");
    rewind.type = "button";
    rewind.className = "voice-step";
    rewind.setAttribute("aria-label", "Rewind 5 seconds");
    setPlaybackIcon(rewind, "rewind");
    forward.type = "button";
    forward.className = "voice-step";
    forward.setAttribute("aria-label", "Forward 5 seconds");
    setPlaybackIcon(forward, "forward");
    seek.type = "range";
    seek.className = "voice-seek";
    seek.min = "0";
    seek.max = String(duration);
    seek.step = "0.01";
    seek.value = "0";
    seek.setAttribute("aria-label", "Voice message position");
    time.className = "voice-time";
    time.textContent = `0:00 / ${formatPlaybackTime(duration)}`;

    const currentTime = () =>
      source
        ? Math.min(
            offset + (playbackContext().currentTime - startedAt),
            duration,
          )
        : offset;
    const renderTime = () => {
      const current = currentTime();
      seek.value = String(current);
      time.textContent = `${formatPlaybackTime(current)} / ${formatPlaybackTime(duration)}`;
    };
    const tick = () => {
      renderTime();
      if (source) {
        frame = requestAnimationFrame(tick);
      }
    };
    const stop = () => {
      if (!source) {
        return;
      }
      source.onended = null;
      source.stop();
      source.disconnect();
      source = null;
      cancelAnimationFrame(frame);
      setPlaybackIcon(button, "play");
      button.setAttribute("aria-label", "Play voice message");
    };
    const play = async () => {
      stop();
      if (offset >= duration) {
        offset = 0;
      }
      await playbackContext().resume();
      source = playbackContext().createBufferSource();
      source.buffer = buffer;
      source.connect(playbackContext().destination);
      startedAt = playbackContext().currentTime;
      source.onended = () => {
        source = null;
        offset = 0;
        cancelAnimationFrame(frame);
        setPlaybackIcon(button, "play");
        button.setAttribute("aria-label", "Play voice message");
        renderTime();
      };
      source.start(0, offset);
      setPlaybackIcon(button, "pause");
      button.setAttribute("aria-label", "Pause voice message");
      tick();
    };
    const pause = () => {
      offset = currentTime();
      stop();
      renderTime();
    };
    const seekTo = (seconds) => {
      const wasPlaying = Boolean(source);
      offset = Math.max(0, Math.min(seconds, duration));
      if (wasPlaying) {
        play().catch((error) => status(error.message, true));
      } else {
        renderTime();
      }
    };

    renderTime();
    state.voiceStops.add(stop);
    window.addEventListener("beforeunload", stop, { once: true });
    button.addEventListener("click", () => {
      if (source) {
        pause();
      } else {
        play().catch((error) => status(error.message, true));
      }
    });
    seek.addEventListener("input", () => {
      seekTo(Number(seek.value));
    });
    seek.addEventListener("change", () => {
      seekTo(Number(seek.value));
    });
    rewind.addEventListener("click", () => {
      seekTo(currentTime() - 5);
    });
    forward.addEventListener("click", () => {
      seekTo(currentTime() + 5);
    });

    player.append(button, rewind, seek, time, forward);
    return player;
  }
  const text = document.createElement("p");
  text.className = "message-text";
  text.textContent = payload.text;
  return text;
}

async function loadMessages(options = {}) {
  if (state.loadingMessages) {
    state.pendingMessageLoad = {
      scrollToBottom:
        Boolean(state.pendingMessageLoad?.scrollToBottom) ||
        Boolean(options.scrollToBottom),
    };
    return;
  }
  state.loadingMessages = true;
  try {
    await renderMessages(options);
  } finally {
    state.loadingMessages = false;
  }
  const pending = state.pendingMessageLoad;
  state.pendingMessageLoad = null;
  if (pending) {
    await loadMessages(pending);
  }
}

async function renderMessages({ scrollToBottom = false } = {}) {
  const scrollFromBottom =
    els.messages.scrollHeight -
    els.messages.scrollTop -
    els.messages.clientHeight;
  state.messages = await apiJson(await signedFetch("/messages?limit=100"));
  await syncMessageState();
  renderClients();
  await renderMessagesFromState({ scrollToBottom, scrollFromBottom });
}

async function renderMessagesFromState({
  scrollToBottom = false,
  scrollFromBottom = els.messages.scrollHeight -
    els.messages.scrollTop -
    els.messages.clientHeight,
} = {}) {
  if (!state.selected) {
    state.voiceStops.forEach((stop) => stop());
    state.voiceStops.clear();
    clearReplyTarget();
    els.messages.replaceChildren();
    return;
  }
  const visibleIds = new Set(
    state.messages
      .filter((message) => peerId(message) === state.selected.id)
      .map((message) => message.id),
  );
  for (const messageId of state.selectedMessageIds) {
    if (!visibleIds.has(messageId)) {
      state.selectedMessageIds.delete(messageId);
    }
  }
  if (state.replyTarget && !visibleIds.has(state.replyTarget.id)) {
    clearReplyTarget();
  }
  updateSelectionUi();
  const nextMessages = document.createDocumentFragment();
  const nextStops = new Set();
  const previousStops = state.voiceStops;
  state.voiceStops = nextStops;
  let lastDay = "";
  for (const message of state.messages) {
    if (state.selected && peerId(message) !== state.selected.id) {
      continue;
    }
    const sentAt = messageDate(message);
    const currentDay = dayKey(sentAt);
    if (currentDay !== lastDay) {
      const divider = document.createElement("div");
      divider.className = "day-divider";
      divider.textContent = formatMessageDay(sentAt);
      nextMessages.append(divider);
      lastDay = currentDay;
    }
    const item = document.createElement("article");
    item.className =
      message.sender_id === state.identity.clientId ? "message own" : "message";
    item.dataset.messageId = message.id;
    item.classList.toggle("selected", state.selectedMessageIds.has(message.id));
    item.addEventListener("click", () => {
      if (state.selectedMessageIds.size > 0) {
        toggleMessageSelection(message);
      }
    });
    item.addEventListener("contextmenu", (event) => {
      showMessageMenu(event, message);
    });
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent =
      message.sender_id === state.identity.clientId
        ? `to ${message.recipient_id} - ${messageState(message)} - ${formatMessageTime(sentAt)}`
        : `from ${message.sender_id} - ${formatMessageTime(sentAt)}`;
    item.append(meta);
    const forwardedFrom = await renderForwardedFrom(message);
    if (forwardedFrom) {
      item.append(forwardedFrom);
    }
    if (message.reply_to_id) {
      item.append(await renderReplyQuote(message.reply_to_id));
    }
    item.append(await renderMessageBody(message));
    nextMessages.append(item);
  }
  previousStops.forEach((stop) => stop());
  els.messages.replaceChildren(nextMessages);
  els.messages.scrollTop = scrollToBottom
    ? els.messages.scrollHeight
    : els.messages.scrollHeight - els.messages.clientHeight - scrollFromBottom;
}

function renderClients() {
  els.clients.replaceChildren();
  for (const client of state.clients) {
    const isSelf = client.id === state.identity?.clientId;
    const node = els.clientTemplate.content.firstElementChild.cloneNode(true);
    node.classList.toggle("active", state.selected?.id === client.id);
    node.classList.toggle("self", isSelf);
    node.classList.toggle(
      "forward-target",
      state.forwardingMessages.length > 0,
    );
    node.disabled = state.forwardingMessages.length > 0 && isSelf;
    node.querySelector(".client-name").textContent = client.display_name;
    const count = unreadCount(client.id);
    node.querySelector(".client-id").textContent = isSelf
      ? `${client.id} - you`
      : client.id;
    if (count > 0) {
      const badge = document.createElement("span");
      badge.className = "unread";
      badge.textContent = String(count);
      node.append(badge);
    }
    node.addEventListener("click", () => {
      (async () => {
        if (state.forwardingMessages.length > 0) {
          await forwardMessagesTo(client);
          return;
        }
        state.selectedMessageIds.clear();
        updateSelectionUi();
        clearReplyTarget();
        state.selected = client;
        localStorage.setItem(selectedKey, client.id);
        els.chatTitle.textContent = client.display_name;
        renderClients();
        await loadMessages();
        await loadCalls();
      })().catch((error) => status(error.message, true));
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
els.startCall.addEventListener("click", () => {
  startCall().catch((error) => status(error.message, true));
});
els.acceptCall.addEventListener("click", () => {
  acceptCall().catch((error) => status(error.message, true));
});
els.declineCall.addEventListener("click", declineCall);
els.muteCall.addEventListener("click", () => {
  state.callMuted = !state.callMuted;
  applyCallTrackState();
  sendCallState().catch((error) => status(error.message, true));
});
els.cameraCall.addEventListener("click", () => {
  (state.callCameraOff ? enableCamera() : disableCamera()).catch((error) =>
    status(error.message, true),
  );
});
els.toggleCallSize.addEventListener("click", () => {
  state.callCollapsedManual = !state.callCollapsedManual;
  updateCallUi();
});
els.leaveCall.addEventListener("click", () => {
  leaveCall(true).catch((error) => status(error.message, true));
});
els.settingsModal.addEventListener("click", (event) => {
  if (event.target === els.settingsModal) {
    closeSettings();
  }
});
document.addEventListener("click", () => {
  closeContextMenu();
  closeAttachmentMenu();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeContextMenu();
    closeAttachmentMenu();
    if (state.forwardingMessages.length > 0) {
      cancelForwarding();
    } else if (state.selectedMessageIds.size > 0) {
      exitSelection();
    } else if (state.replyTarget) {
      clearReplyTarget();
    }
  }
});
els.messages.addEventListener("scroll", closeContextMenu);
els.openAttachments.addEventListener("click", (event) => {
  event.stopPropagation();
  setAttachmentMenu(els.attachmentMenu.hidden);
});
els.attachmentMenu.addEventListener("click", (event) => {
  event.stopPropagation();
});
els.cancelSelection.addEventListener("click", exitSelection);
els.deleteSelected.addEventListener("click", () => {
  deleteSelectedMessages().catch((error) => status(error.message, true));
});
els.forwardSelected.addEventListener("click", () => {
  const selectedMessages = state.messages.filter((message) =>
    state.selectedMessageIds.has(message.id),
  );
  beginForwarding(selectedMessages);
});
els.cancelForwarding.addEventListener("click", cancelForwarding);
els.cancelReply.addEventListener("click", clearReplyTarget);
els.messageForm.addEventListener("submit", (event) => {
  sendMessage(event).catch((error) => status(error.message, true));
});
els.messageText.addEventListener("input", resizeMessageText);
els.recordVoice.addEventListener("click", () => {
  startVoiceRecording().catch((error) => status(error.message, true));
});
els.pickImage.addEventListener("click", () => {
  closeAttachmentMenu();
  els.imageInput.click();
});
els.pickFile.addEventListener("click", () => {
  closeAttachmentMenu();
  els.fileInput.click();
});
els.imageInput.addEventListener("change", () => {
  const file = els.imageInput.files?.[0];
  els.imageInput.value = "";
  if (file) {
    sendAttachment(file, "image").catch((error) => status(error.message, true));
  }
});
els.fileInput.addEventListener("change", () => {
  const file = els.fileInput.files?.[0];
  els.fileInput.value = "";
  if (file) {
    sendAttachment(file, "file").catch((error) => status(error.message, true));
  }
});
els.cancelVoice.addEventListener("click", () => {
  stopVoiceRecording(false);
});
els.sendVoice.addEventListener("click", () => {
  stopVoiceRecording(true);
});

if (savedIdentity) {
  resizeMessageText();
  loadIdentity();
  connectEvents();
}
