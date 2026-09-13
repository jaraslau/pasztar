export const storeKey = "pasztar.identity";
export const pendingKey = "pasztar.pendingIdentity";
export const selectedKey = "pasztar.selectedClient";
export const mediaInputKey = "pasztar.mediaInputs";
export const maxRecordingMs = 60000;
export const maxAttachmentBytes = 100 * 1024 * 1024;
export const maxImageDimension = 1600;
export const eventReconnectBaseMs = 2000;
export const eventReconnectMaxMs = 30000;
export const clientHeartbeatMs = 15000;
export const clientOnlineMs = 45000;
export const callHeartbeatMs = 10000;

function savedMediaInputs() {
  try {
    return JSON.parse(localStorage.getItem(mediaInputKey)) || {};
  } catch {
    return {};
  }
}

const mediaInputs = savedMediaInputs();

export const state = {
  identity: null,
  clients: [],
  messages: [],
  selected: null,
  refreshing: false,
  loadingMessages: false,
  pendingMessageLoad: null,
  eventsConnecting: false,
  eventReconnectMs: eventReconnectBaseMs,
  clientHeartbeat: null,
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
  callConfigLoaded: false,
  callIceServers: [],
  declinedCallIds: new Set(),
  activeCall: null,
  activeCallPeerId: null,
  callStarting: false,
  callMuted: false,
  callCameraOff: true,
  callScreenSharing: false,
  callCameraWasOffBeforeShare: true,
  callMediaBusy: false,
  callPeerMuted: false,
  callPeerCameraOff: true,
  callCollapsedManual: false,
  callStream: null,
  callAudioSender: null,
  callVideoSender: null,
  remoteStream: null,
  callPeerVideoLive: false,
  peerConnection: null,
  callMakingOffer: false,
  callIgnoreOffer: false,
  callRestarting: false,
  callReconnectTimer: null,
  callSignalsSeen: new Set(),
  callPendingCandidates: [],
  callHeartbeat: null,
  selectedAudioInputId: mediaInputs.audio || "",
  selectedVideoInputId: mediaInputs.video || "",
};

export const savedIdentity = localStorage.getItem(storeKey);
if (!savedIdentity) {
  location.replace("/setup.html");
}

export const els = {
  appStatus: document.querySelector("#app-status"),
  clients: document.querySelector("#clients"),
  refreshClients: document.querySelector("#refresh-clients"),
  openSettings: document.querySelector("#open-settings"),
  closeSettings: document.querySelector("#close-settings"),
  settingsModal: document.querySelector("#settings-modal"),
  identitySummary: document.querySelector("#identity-summary"),
  invitations: document.querySelector("#invitations"),
  createInvitation: document.querySelector("#create-invitation"),
  invitationResult: document.querySelector("#invitation-result"),
  invitationLink: document.querySelector("#invitation-link"),
  copyInvitation: document.querySelector("#copy-invitation"),
  invitationStatus: document.querySelector("#invitation-status"),
  audioInput: document.querySelector("#audio-input"),
  videoInput: document.querySelector("#video-input"),
  chatTitle: document.querySelector("#chat-title"),
  shell: document.querySelector(".shell"),
  chat: document.querySelector(".chat"),
  backToClients: document.querySelector("#back-to-clients"),
  startCall: document.querySelector("#start-call"),
  callPanel: document.querySelector("#call-panel"),
  callStage: document.querySelector(".call-stage"),
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
  screenCall: document.querySelector("#screen-call"),
  toggleCallSize: document.querySelector("#toggle-call-size"),
  fullscreenCall: document.querySelector("#fullscreen-call"),
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
  clientsForwardingBar: document.querySelector("#clients-forwarding-bar"),
  clientsForwardingCount: document.querySelector("#clients-forwarding-count"),
  cancelForwardingClients: document.querySelector("#cancel-forwarding-clients"),
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

export function inputDeviceConstraint(deviceId) {
  return deviceId ? { deviceId: { exact: deviceId } } : true;
}

export function status(text, error = false) {
  els.appStatus.textContent = text;
  els.appStatus.classList.toggle("error", error);
}

export function truncateText(value, length = 92) {
  return value.length > length ? `${value.slice(0, length - 1)}...` : value;
}

export function displayNameForId(clientId) {
  if (clientId === state.identity.clientId) {
    return "You";
  }
  return (
    state.clients.find((client) => client.id === clientId)?.display_name ||
    clientId
  );
}

export function messageDate(message) {
  return new Date(message.created_at);
}

export function dayKey(date) {
  return [
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, "0"),
    String(date.getDate()).padStart(2, "0"),
  ].join("-");
}

export function formatMessageDay(date) {
  return new Intl.DateTimeFormat(undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
  }).format(date);
}

export function formatMessageTime(date) {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function attachmentName(name, fallback) {
  const trimmed = (name || "").trim();
  return trimmed || fallback;
}

export function iconNode(icon) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  svg.classList.add("icon");
  use.setAttribute("href", `#icon-${icon}`);
  svg.append(use);
  return svg;
}

export function setButtonIcon(button, icon) {
  button.innerHTML = `<svg class="icon"><use href="#icon-${icon}"></use></svg>`;
}
