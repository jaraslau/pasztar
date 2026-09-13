import {
  attachmentName,
  clientOnlineMs,
  dayKey,
  displayNameForId,
  els,
  formatMessageDay,
  formatMessageTime,
  iconNode,
  inputDeviceConstraint,
  maxAttachmentBytes,
  maxImageDimension,
  maxRecordingMs,
  messageDate,
  selectedKey,
  state,
  status,
  truncateText,
} from "./context.js";
import { apiJson, decryptMessage, encryptFor, signedFetch } from "./crypto.js";

let hooks = {};
const forwardLineColors = [
  "#7cc7ff",
  "#f08ac4",
  "#a6d96a",
  "#c69cff",
  "#f4c95d",
  "#6fd6d2",
];

export function setMessageHooks(nextHooks) {
  hooks = nextHooks;
}

function forwardLineColor(clientId) {
  let hash = 0;
  for (const char of clientId || "") {
    hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  }
  return forwardLineColors[hash % forwardLineColors.length];
}

export function messageAuthor(message) {
  return displayNameForId(message.sender_id);
}

function summarizePayload(payload) {
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

async function messagePayload(message, payloads) {
  if (!payloads) {
    return decryptMessage(message);
  }
  if (!payloads.has(message.id)) {
    payloads.set(message.id, decryptMessage(message));
  }
  return payloads.get(message.id);
}

export async function messageSummary(message) {
  return summarizePayload(await decryptMessage(message));
}

export function clearReplyTarget() {
  state.replyTarget = null;
  els.replyPreview.hidden = true;
  els.replyPreviewText.textContent = "";
}

export async function updateReplyUi() {
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

export async function setReplyTarget(message) {
  if (state.selectedMessageIds.size > 0) {
    state.selectedMessageIds.clear();
    updateSelectionUi();
  }
  state.replyTarget = message;
  await updateReplyUi();
  els.messageText.focus();
}

export function closeContextMenu() {
  state.contextMenu?.remove();
  state.contextMenu = null;
}

export function setAttachmentMenu(open) {
  els.attachmentMenu.hidden = !open;
  els.messageForm.classList.toggle("attachments-open", open);
  els.openAttachments.setAttribute("aria-expanded", String(open));
}

export function closeAttachmentMenu() {
  setAttachmentMenu(false);
}

export function updateSelectionUi() {
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
  els.clientsForwardingBar.hidden = !forwarding;
  els.clientsForwardingCount.textContent = forwarding
    ? `Forwarding ${state.forwardingMessages.length} message${
        state.forwardingMessages.length === 1 ? "" : "s"
      }`
    : "";
  els.chat.classList.toggle("forwarding", forwarding);
  els.clientsPanel.classList.toggle("forwarding", forwarding);
  els.cancelForwarding.disabled = state.forwardingSending;
  els.cancelForwardingClients.disabled = state.forwardingSending;
}

export function exitSelection() {
  state.selectedMessageIds.clear();
  updateSelectionUi();
  renderMessagesFromState().catch((error) => status(error.message, true));
}

export function toggleMessageSelection(message) {
  if (state.selectedMessageIds.has(message.id)) {
    state.selectedMessageIds.delete(message.id);
  } else {
    state.selectedMessageIds.add(message.id);
  }
  updateSelectionUi();
  renderMessagesFromState().catch((error) => status(error.message, true));
}

export function enterSelection(message) {
  if (state.recording) {
    stopVoiceRecording(false);
  }
  clearReplyTarget();
  state.selectedMessageIds.add(message.id);
  updateSelectionUi();
  renderMessagesFromState().catch((error) => status(error.message, true));
}

export async function loadClients() {
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
  await hooks.afterClientsLoaded?.();
}

export function isIncoming(message) {
  return message.recipient_id === state.identity.clientId;
}

export function peerId(message) {
  return message.sender_id === state.identity.clientId
    ? message.recipient_id
    : message.sender_id;
}

export function messageState(message) {
  if (message.read_at) {
    return "read";
  }
  if (message.delivered_at) {
    return "delivered";
  }
  return "sent";
}

export function unreadCount(clientId) {
  return state.messages.filter(
    (message) =>
      isIncoming(message) && message.sender_id === clientId && !message.read_at,
  ).length;
}

function isClientOnline(client) {
  const lastSeen = Date.parse(client.last_seen);
  return Number.isFinite(lastSeen) && Date.now() - lastSeen <= clientOnlineMs;
}

function messageMinuteKey(date) {
  return [
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
    date.getHours(),
    date.getMinutes(),
  ].join(":");
}

function emptyMessages() {
  const logo = document.createElement("img");
  const empty = document.createElement("p");
  const wrapper = document.createElement("div");
  logo.src = "/assets/pasztar.png";
  logo.alt = "";
  wrapper.className = "empty-chat";
  empty.className = "empty-chat-text";
  empty.textContent = "Nothing here yet";
  wrapper.append(logo, empty);
  els.messages.replaceChildren(wrapper);
}

export async function markMessage(message, stateName) {
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

export async function syncMessageState() {
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

export function formatDuration(ms) {
  const seconds = Math.ceil(ms / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

export function formatPlaybackTime(seconds) {
  if (!Number.isFinite(seconds)) {
    return "0:00";
  }
  const whole = Math.floor(seconds);
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, "0")}`;
}

export function setPlaybackIcon(button, icon) {
  button.innerHTML = `<svg class="icon"><use href="#icon-${icon}"></use></svg>`;
}

export function playbackContext() {
  state.audioContext =
    state.audioContext ||
    new (window.AudioContext || window.webkitAudioContext)();
  return state.audioContext;
}

export function updateRecordingUi() {
  const recording = state.recording;
  els.recordVoice.hidden = Boolean(recording);
  els.voiceControls.hidden = !recording;
  els.cancelVoice.disabled = Boolean(recording?.stopping);
  els.sendVoice.disabled = Boolean(recording?.stopping);
  els.voiceTimer.textContent = recording
    ? formatDuration(Math.min(Date.now() - recording.startedAt, maxRecordingMs))
    : "0:00";
}

export function resizeMessageText() {
  els.messageText.style.height = "46px";
  els.messageText.style.height = `${Math.min(
    els.messageText.scrollHeight,
    160,
  )}px`;
  els.sendText.hidden = els.messageText.value.trim() === "";
}

export function recordingMimeType() {
  return window.MediaRecorder?.isTypeSupported?.("audio/webm;codecs=opus")
    ? "audio/webm;codecs=opus"
    : "";
}

export async function startVoiceRecording() {
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
    stream = await navigator.mediaDevices.getUserMedia({
      audio: inputDeviceConstraint(state.selectedAudioInputId),
    });
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

export function stopVoiceRecording(send) {
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

export async function finishVoiceRecording(recording) {
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

export function compressedImageName(name) {
  return attachmentName(name, "image.jpg").replace(/\.[^.]*$/, "") + ".jpg";
}

export async function compressImage(file) {
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

export async function prepareAttachment(file, kind) {
  if (kind === "image") {
    return compressImage(file);
  }
  return {
    blob: file,
    name: attachmentName(file.name, "attachment"),
    mimeType: file.type || "application/octet-stream",
  };
}

export async function postEncryptedMessage(
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

export async function sendMessage(event) {
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

export async function sendVoiceMessage(blob, durationMs, recipient) {
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

export async function sendAttachment(file, kind) {
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

export async function sendCallEventMessage(eventName, recipient) {
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

export async function deleteMessageId(messageId) {
  await apiJson(
    await signedFetch(`/messages/${encodeURIComponent(messageId)}`, {
      method: "DELETE",
    }),
  );
}

export async function runLimited(items, limit, task) {
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

export async function deleteMessage(message) {
  if (!confirm("Delete this message for both sides?")) {
    return;
  }
  await deleteMessageId(message.id);
  status("Message deleted.");
  await loadMessages();
}

export async function deleteSelectedMessages() {
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

export function cancelForwarding() {
  if (state.forwardingSending) {
    return;
  }
  state.forwardingMessages = [];
  updateSelectionUi();
  renderClients();
}

export function beginForwarding(messages) {
  if (!messages.length) {
    return;
  }
  if (state.recording) {
    stopVoiceRecording(false);
  }
  clearReplyTarget();
  state.selectedMessageIds.clear();
  state.forwardingMessages = messages;
  els.shell.classList.remove("chat-open");
  updateSelectionUi();
  renderClients();
  renderMessagesFromState().catch((error) => status(error.message, true));
}

export async function encryptForwardedMessage(message, recipient) {
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

export function downloadAttachment(payload) {
  const blob = new Blob([payload.data], { type: payload.mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = payload.name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function forwardMessagesTo(recipient) {
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
    els.shell.classList.add("chat-open");
    status(`${count} message${count === 1 ? "" : "s"} forwarded.`);
    updateSelectionUi();
    renderClients();
    await loadMessages({ scrollToBottom: true });
  } finally {
    state.forwardingSending = false;
    updateSelectionUi();
  }
}

export function showMessageMenuAt(message, x, y) {
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
  menu.style.left = `${Math.min(x, innerWidth - rect.width - 8)}px`;
  menu.style.top = `${Math.min(y, innerHeight - rect.height - 8)}px`;
}

export function showMessageMenu(event, message) {
  event.preventDefault();
  showMessageMenuAt(message, event.clientX, event.clientY);
}

function bindMessageLongPress(item, message) {
  let timer = 0;
  let startX = 0;
  let startY = 0;
  let opened = false;
  const clear = () => {
    clearTimeout(timer);
    timer = 0;
  };
  item.addEventListener("pointerdown", (event) => {
    if (
      event.pointerType === "mouse" ||
      event.target.closest("button, input, textarea, a")
    ) {
      return;
    }
    opened = false;
    startX = event.clientX;
    startY = event.clientY;
    clear();
    timer = setTimeout(() => {
      opened = true;
      event.preventDefault();
      showMessageMenuAt(message, startX, startY);
    }, 550);
  });
  item.addEventListener("pointermove", (event) => {
    if (Math.hypot(event.clientX - startX, event.clientY - startY) > 10) {
      clear();
    }
  });
  for (const eventName of ["pointerup", "pointercancel", "pointerleave"]) {
    item.addEventListener(eventName, clear);
  }
  item.addEventListener(
    "click",
    (event) => {
      if (opened) {
        event.preventDefault();
        event.stopPropagation();
        opened = false;
      }
    },
    true,
  );
}

export function scrollToMessage(messageId) {
  const node = [...els.messages.children].find(
    (item) => item.dataset.messageId === messageId,
  );
  node?.scrollIntoView({ block: "center", behavior: "smooth" });
}

export async function renderReplyQuote(replyToId, payloads = null) {
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
    ? summarizePayload(await messagePayload(original, payloads))
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

export function renderForwardedFrom(message, payload) {
  if (!payload.forwardedFrom) {
    return null;
  }
  const forwarded = document.createElement("p");
  forwarded.className = "forwarded-from";
  forwarded.dataset.forwardedFrom = payload.forwardedFrom;
  forwarded.textContent = `Forwarded from ${displayNameForId(payload.forwardedFrom)}`;
  return forwarded;
}

export async function renderMessageBody(message, payload) {
  if (payload.kind === "call_event") {
    if (!["started", "ended"].includes(payload.event)) {
      return null;
    }
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

export async function loadMessages(options = {}) {
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

export async function renderMessages({ scrollToBottom = false } = {}) {
  const scrollFromBottom =
    els.messages.scrollHeight -
    els.messages.scrollTop -
    els.messages.clientHeight;
  state.messages = await apiJson(await signedFetch("/messages?limit=100"));
  await syncMessageState();
  renderClients();
  await renderMessagesFromState({ scrollToBottom, scrollFromBottom });
}

export async function renderMessagesFromState({
  scrollToBottom = false,
  scrollFromBottom = els.messages.scrollHeight -
    els.messages.scrollTop -
    els.messages.clientHeight,
} = {}) {
  if (!state.selected) {
    state.voiceStops.forEach((stop) => stop());
    state.voiceStops.clear();
    clearReplyTarget();
    emptyMessages();
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
  const payloads = new Map();
  let lastDay = "";
  let previousGroup = null;
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
      previousGroup = null;
    }
    const item = document.createElement("article");
    const isOwn = message.sender_id === state.identity.clientId;
    item.className = isOwn ? "message own" : "message incoming";
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
    bindMessageLongPress(item, message);
    if (isOwn) {
      item.dataset.status = messageState(message);
    }
    const content = document.createElement("div");
    content.className = "message-content";
    const metaTime = document.createElement("span");
    metaTime.className = "meta-time";
    metaTime.textContent = formatMessageTime(sentAt);
    item.append(metaTime);
    const payload = await messagePayload(message, payloads);
    const forwardedFrom = renderForwardedFrom(message, payload);
    if (forwardedFrom) {
      item.classList.add("forwarded-message");
      item.style.setProperty(
        "--forward-line",
        forwardLineColor(forwardedFrom.dataset.forwardedFrom),
      );
      content.append(forwardedFrom);
    }
    if (message.reply_to_id) {
      content.append(await renderReplyQuote(message.reply_to_id, payloads));
    }
    const body = await renderMessageBody(message, payload);
    if (!body) {
      continue;
    }
    const isCallEvent = body.classList.contains("call-event-message");
    if (isCallEvent) {
      item.className = "message call-event-row";
    }
    const group = {
      item,
      senderId: message.sender_id,
      minute: messageMinuteKey(sentAt),
      allowed: !isCallEvent && !message.reply_to_id && !forwardedFrom,
    };
    if (
      group.allowed &&
      previousGroup?.allowed &&
      previousGroup.senderId === group.senderId &&
      previousGroup.minute === group.minute
    ) {
      previousGroup.item.classList.add("message-group-start");
      item.classList.add("message-group-continuation");
    }
    content.append(body);
    const metaWho = document.createElement("p");
    metaWho.className = "meta-who";
    metaWho.textContent = isOwn
      ? `to ${message.recipient_id}`
      : `from ${message.sender_id}`;
    content.append(metaWho);
    item.append(content);
    nextMessages.append(item);
    previousGroup = group.allowed ? group : null;
  }
  previousStops.forEach((stop) => stop());
  if (nextMessages.childNodes.length === 0) {
    emptyMessages();
  } else {
    els.messages.replaceChildren(nextMessages);
  }
  els.messages.scrollTop = scrollToBottom
    ? els.messages.scrollHeight
    : els.messages.scrollHeight - els.messages.clientHeight - scrollFromBottom;
}

export function renderClients() {
  els.clients.replaceChildren();
  els.inactiveClients.replaceChildren();
  let inactiveCount = 0;
  const clients = [...state.clients].sort(
    (a, b) => Number(isClientOnline(b)) - Number(isClientOnline(a)),
  );
  for (const client of clients) {
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
    const online = isClientOnline(client);
    node.classList.toggle("online", online);
    const count = unreadCount(client.id);
    node.querySelector(".client-id").textContent = isSelf
      ? `${client.id} - you`
      : client.id;
    if (count > 0) {
      const badge = document.createElement("span");
      badge.className = "unread";
      badge.textContent = String(count);
      node.querySelector(".client-status").append(badge);
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
        els.shell.classList.add("chat-open");
        renderClients();
        await loadMessages();
        await hooks.afterClientSelected?.();
      })().catch((error) => status(error.message, true));
    });
    const inactive = client.inactive && !isSelf;
    if (inactive) inactiveCount += 1;
    (inactive ? els.inactiveClients : els.clients).append(node);
  }
  els.inactiveSection.hidden = inactiveCount === 0;
  els.inactiveSummary.textContent = `Inactive identities (${inactiveCount})`;
}
