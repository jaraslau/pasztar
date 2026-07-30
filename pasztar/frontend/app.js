const storeKey = "pasztar.identity";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  identity: null,
  clients: [],
  selected: null,
};

const savedIdentity = localStorage.getItem(storeKey);
if (!savedIdentity) {
  location.replace("/setup.html");
}

const els = {
  appStatus: document.querySelector("#app-status"),
  clients: document.querySelector("#clients"),
  refreshClients: document.querySelector("#refresh-clients"),
  chatTitle: document.querySelector("#chat-title"),
  messages: document.querySelector("#messages"),
  exportIdentity: document.querySelector("#export-identity"),
  refreshMessages: document.querySelector("#refresh-messages"),
  messageForm: document.querySelector("#message-form"),
  messageText: document.querySelector("#message-text"),
  clientTemplate: document.querySelector("#client-template"),
};

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function bytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
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
}

function exportIdentity() {
  const blob = new Blob([JSON.stringify(state.identity, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `pasztar-${state.identity.clientId}-identity.json`;
  link.click();
  URL.revokeObjectURL(url);
  status("Identity bundle exported.");
}

function loadIdentity() {
  try {
    saveIdentity(JSON.parse(savedIdentity));
    loadClients().catch((error) => status(error.message, true));
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
      "X-Identity-Token": state.identity.identityToken,
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
  renderClients();
}

async function encryptFor(recipient, text) {
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
    encoder.encode(text),
  );
  return JSON.stringify({
    v: 1,
    alg: "ECDH-P256+A256GCM",
    sender_epk: state.identity.encryptionPublicKey,
    iv: b64(iv),
    data: b64(ciphertext),
  });
}

async function decryptMessage(message) {
  try {
    const envelope = JSON.parse(message.ciphertext);
    const peerKey =
      message.sender_id === state.identity.clientId
        ? state.clients.find((client) => client.id === message.recipient_id)
            ?.encryption_public_key
        : envelope.sender_epk;
    if (!peerKey || envelope.v !== 1) {
      return "[unable to decrypt]";
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
    return decoder.decode(plaintext);
  } catch {
    return "[unable to decrypt]";
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
  await loadMessages();
}

async function loadMessages() {
  const messages = await apiJson(await signedFetch("/messages?limit=100"));
  els.messages.replaceChildren();
  for (const message of messages) {
    if (
      state.selected &&
      message.sender_id !== state.selected.id &&
      message.recipient_id !== state.selected.id
    ) {
      continue;
    }
    const item = document.createElement("article");
    item.className =
      message.sender_id === state.identity.clientId ? "message own" : "message";
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = `${message.sender_id} -> ${message.recipient_id}`;
    const text = document.createElement("p");
    text.className = "message-text";
    text.textContent = await decryptMessage(message);
    item.append(meta, text);
    els.messages.append(item);
  }
}

function renderClients() {
  els.clients.replaceChildren();
  for (const client of state.clients) {
    const isSelf = client.id === state.identity?.clientId;
    const node = els.clientTemplate.content.firstElementChild.cloneNode(true);
    node.classList.toggle("active", state.selected?.id === client.id);
    node.classList.toggle("self", isSelf);
    node.querySelector(".client-name").textContent = client.display_name;
    node.querySelector(".client-id").textContent = isSelf ? `${client.id} - you` : client.id;
    node.addEventListener("click", async () => {
      state.selected = client;
      els.chatTitle.textContent = client.display_name;
      renderClients();
      await loadMessages();
    });
    els.clients.append(node);
  }
}

els.refreshClients.addEventListener("click", () => {
  loadClients().catch((error) => status(error.message, true));
});
els.refreshMessages.addEventListener("click", () => {
  loadMessages().catch((error) => status(error.message, true));
});
els.exportIdentity.addEventListener("click", exportIdentity);
els.messageForm.addEventListener("submit", (event) => {
  sendMessage(event).catch((error) => status(error.message, true));
});

if (savedIdentity) {
  loadIdentity();
}
