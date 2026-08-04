import {
  els,
  clientHeartbeatMs,
  eventReconnectBaseMs,
  eventReconnectMaxMs,
  pendingKey,
  savedIdentity,
  selectedKey,
  state,
  status,
} from "./context.js";
import { apiJson, b64, bundleKey, signedFetch } from "./crypto.js";
import { decoder } from "./crypto_core.js";
import {
  beginForwarding,
  cancelForwarding,
  clearReplyTarget,
  closeAttachmentMenu,
  closeContextMenu,
  deleteSelectedMessages,
  exitSelection,
  loadClients,
  loadMessages,
  resizeMessageText,
  sendAttachment,
  sendMessage,
  setMessageHooks,
  startVoiceRecording,
  stopVoiceRecording,
  renderClients,
} from "./messages.js";
import {
  acceptCall,
  applyCallTrackState,
  declineCall,
  disableCamera,
  enableCamera,
  leaveCall,
  loadCalls,
  sendCallState,
  startCall,
  updateCallUi,
} from "./calls.js";

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
    new TextEncoder().encode(JSON.stringify(state.identity)),
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
  localStorage.removeItem("pasztar.identity");
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
    localStorage.removeItem("pasztar.identity");
    location.replace("/setup.html");
  }
}

async function refresh() {
  if (state.refreshing) {
    return;
  }
  state.refreshing = true;
  els.refreshClients.classList.add("refreshing");
  try {
    await loadClients();
    await loadMessages();
    await loadCalls();
  } finally {
    state.refreshing = false;
    els.refreshClients.classList.remove("refreshing");
  }
}

async function handleEvent(eventName) {
  if (eventName === "ready") {
    state.eventReconnectMs = eventReconnectBaseMs;
    status("Event stream connected.");
    await refresh();
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

function startClientHeartbeat() {
  if (state.clientHeartbeat) {
    return;
  }
  const beat = () => {
    signedFetch("/heartbeat", { method: "POST" })
      .then(apiJson)
      .then(({ last_seen }) => {
        const self = state.clients.find(
          (client) => client.id === state.identity.clientId,
        );
        if (self) {
          self.last_seen = last_seen;
          renderClients();
        }
      })
      .catch((error) => status(error.message, true));
  };
  beat();
  state.clientHeartbeat = setInterval(() => {
    beat();
    renderClients();
  }, clientHeartbeatMs);
}

setMessageHooks({
  afterClientsLoaded: updateCallUi,
  afterClientSelected: loadCalls,
});

els.refreshClients.addEventListener("click", () => {
  refresh().catch((error) => status(error.message, true));
});
els.openSettings.addEventListener("click", openSettings);
els.closeSettings.addEventListener("click", closeSettings);
els.exportIdentity.addEventListener("click", () => {
  exportIdentity().catch((error) => status(error.message, true));
});
els.resetIdentity.addEventListener("click", resetIdentity);
els.backToClients.addEventListener("click", () => {
  closeContextMenu();
  closeAttachmentMenu();
  els.shell.classList.remove("chat-open");
});
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
  const open = els.attachmentMenu.hidden;
  els.attachmentMenu.hidden = !open;
  els.messageForm.classList.toggle("attachments-open", open);
  els.openAttachments.setAttribute("aria-expanded", String(open));
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
els.cancelForwardingClients.addEventListener("click", cancelForwarding);
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
  startClientHeartbeat();
  connectEvents();
}
