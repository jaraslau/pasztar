import {
  callHeartbeatMs,
  displayNameForId,
  els,
  setButtonIcon,
  state,
  status,
} from "./context.js";
import { apiJson, decryptMessage, encryptFor, signedFetch } from "./crypto.js";
import { sendCallEventMessage, stopVoiceRecording } from "./messages.js";

export function callPeerId(call) {
  if (!call) {
    return null;
  }
  return call.client_a_id === state.identity.clientId
    ? call.client_b_id
    : call.client_a_id;
}

export function visibleCallForSelected() {
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

export function callHasPeer(call) {
  return Boolean(
    call &&
    state.activeCallPeerId &&
    call.participants.includes(state.identity.clientId) &&
    call.participants.includes(state.activeCallPeerId),
  );
}

export function isCallOfferer() {
  return (
    state.activeCallPeerId &&
    state.identity.clientId.localeCompare(state.activeCallPeerId) < 0
  );
}

export function isPolitePeer() {
  return (
    state.activeCallPeerId &&
    state.identity.clientId.localeCompare(state.activeCallPeerId) > 0
  );
}

export async function loadCallConfig() {
  if (state.callConfigLoaded) {
    return;
  }
  const config = await apiJson(await signedFetch("/calls/config"));
  state.callIceServers = config.ice_servers || [];
  state.callConfigLoaded = true;
}

export function updateCallButtons() {
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

export function updateCallUi() {
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

export function callPeerClient() {
  return state.clients.find((client) => client.id === state.activeCallPeerId);
}

export function closePeerConnection() {
  state.peerConnection?.close();
  state.peerConnection = null;
  state.remoteStream = null;
  state.callMakingOffer = false;
  state.callIgnoreOffer = false;
  state.callPendingCandidates = [];
  els.remoteVideo.srcObject = null;
}

export function stopCallMedia() {
  state.callStream?.getTracks().forEach((track) => track.stop());
  state.callStream = null;
  els.localVideo.srcObject = null;
}

export function clearCallTimers() {
  clearInterval(state.callHeartbeat);
  clearTimeout(state.callReconnectTimer);
  state.callHeartbeat = null;
  state.callReconnectTimer = null;
}

export function cleanupLocalCall() {
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
  state.callRestarting = false;
  updateCallUi();
}

export async function ensureCallMedia() {
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

export function applyCallTrackState() {
  state.callStream
    ?.getAudioTracks()
    .forEach((track) => (track.enabled = !state.callMuted));
  state.callStream
    ?.getVideoTracks()
    .forEach((track) => (track.enabled = !state.callCameraOff));
  updateCallButtons();
  updateCallUi();
}

export async function enableCamera() {
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

export async function disableCamera() {
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

export async function sendCallSignal(type, data) {
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

export async function sendCallState() {
  await sendCallSignal("state", {
    muted: state.callMuted,
    cameraOff: state.callCameraOff,
  }).catch(() => null);
}

export async function flushPendingCandidates() {
  const pending = state.callPendingCandidates.splice(0);
  for (const candidate of pending) {
    await state.peerConnection?.addIceCandidate(candidate);
  }
}

export function scheduleCallReconnect(pc = state.peerConnection, delay = 1200) {
  if (!state.activeCall || state.callReconnectTimer) {
    return;
  }
  state.callReconnectTimer = setTimeout(() => {
    state.callReconnectTimer = null;
    if (!state.activeCall || (pc && state.peerConnection !== pc)) {
      return;
    }
    reconnectCall().catch((error) => status(error.message, true));
  }, delay);
}

export async function reconnectCall() {
  if (state.callRestarting || !callHasPeer(state.activeCall)) {
    return;
  }
  state.callRestarting = true;
  try {
    status("Reconnecting call.");
    closePeerConnection();
    createPeerConnection();
    await sendCallState();
    if (isCallOfferer()) {
      await sendOffer(true, true);
    }
  } finally {
    state.callRestarting = false;
  }
}

export function createPeerConnection() {
  closePeerConnection();
  const pc = new RTCPeerConnection({ iceServers: state.callIceServers });
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
  pc.addEventListener("negotiationneeded", () => {
    sendOffer().catch((error) => status(error.message, true));
  });
  pc.addEventListener("connectionstatechange", () => {
    if (pc.connectionState === "failed") {
      scheduleCallReconnect(pc);
    }
  });
  pc.addEventListener("iceconnectionstatechange", () => {
    if (pc.iceConnectionState === "failed") {
      scheduleCallReconnect(pc);
    }
    if (pc.iceConnectionState === "disconnected") {
      scheduleCallReconnect(pc, 5000);
    }
  });
  return pc;
}

export async function sendOffer(force = false, iceRestart = false) {
  if (!callHasPeer(state.activeCall)) {
    return;
  }
  const pc = state.peerConnection || createPeerConnection();
  if (pc.signalingState !== "stable" || (!force && pc.localDescription)) {
    return;
  }
  state.callMakingOffer = true;
  try {
    const offer = await pc.createOffer(iceRestart ? { iceRestart: true } : {});
    await pc.setLocalDescription(offer);
    await sendCallSignal("offer", pc.localDescription);
  } finally {
    state.callMakingOffer = false;
  }
}

export async function ensurePeerConnectionState() {
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

export async function handleCallSignal(signal) {
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
    const collision = state.callMakingOffer || pc.signalingState !== "stable";
    state.callIgnoreOffer = !isPolitePeer() && collision;
    if (state.callIgnoreOffer) {
      return;
    }
    if (collision) {
      await pc.setLocalDescription({ type: "rollback" });
    }
    state.callIgnoreOffer = false;
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
    try {
      if (pc.remoteDescription) {
        await pc.addIceCandidate(candidate);
      } else {
        state.callPendingCandidates.push(candidate);
      }
    } catch (error) {
      if (!state.callIgnoreOffer) {
        throw error;
      }
    }
  }
}

export async function pollCallSignals() {
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

export function startCallTimers() {
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
}

export async function enterCall(call) {
  if (state.activeCall && state.activeCall.id !== call.id) {
    await leaveCall(true);
  }
  state.declinedCallIds.delete(call.id);
  state.activeCall = call;
  state.activeCallPeerId = callPeerId(call);
  state.callSignalsSeen.clear();
  state.callPendingCandidates = [];
  state.callMuted = false;
  state.callCameraOff = true;
  await loadCallConfig();
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

export async function loadCalls() {
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

export async function startCall() {
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

export async function acceptCall() {
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

export function declineCall() {
  const call = visibleCallForSelected();
  if (call) {
    state.declinedCallIds.add(call.id);
  }
  updateCallUi();
}

export async function leaveCall(notify = true) {
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
