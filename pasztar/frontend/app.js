const storeKey = "pasztar.identity";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  identity: null,
  clients: [],
  selected: null,
};

const els = {
  identityForm: document.querySelector("#identity-form"),
  clientId: document.querySelector("#client-id"),
  displayName: document.querySelector("#display-name"),
  register: document.querySelector("#register"),
  newIdentity: document.querySelector("#new-identity"),
  identityStatus: document.querySelector("#identity-status"),
  clients: document.querySelector("#clients"),
  refreshClients: document.querySelector("#refresh-clients"),
  chatTitle: document.querySelector("#chat-title"),
  messages: document.querySelector("#messages"),
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
  els.identityStatus.textContent = text;
  els.identityStatus.classList.toggle("error", error);
}

function assertCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is unavailable. Use localhost or a secure origin.");
  }
}

async function generateIdentity(clientId, displayName) {
  assertCrypto();
  const signing = await crypto.subtle.generateKey(
    "Ed25519",
    true,
    ["sign", "verify"],
  );
  const encryption = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"],
  );
  const publicKey = b64(await crypto.subtle.exportKey("raw", signing.publicKey));
  const encryptionPublicKey = b64(
    await crypto.subtle.exportKey("spki", encryption.publicKey),
  );

  return {
    clientId,
    displayName,
    publicKey,
    encryptionPublicKey,
    signingPrivateKey: b64(await crypto.subtle.exportKey("pkcs8", signing.privateKey)),
    encryptionPrivateKey: b64(
      await crypto.subtle.exportKey("pkcs8", encryption.privateKey),
    ),
    fingerprint: await fingerprint(publicKey),
  };
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
  localStorage.setItem(storeKey, JSON.stringify(identity));
  els.clientId.value = identity.clientId;
  els.displayName.value = identity.displayName;
  els.clientId.disabled = true;
  els.displayName.disabled = true;
  els.register.disabled = true;
  status(`Loaded ${identity.clientId} (${identity.fingerprint.slice(0, 12)})`);
}

function loadIdentity() {
  const raw = localStorage.getItem(storeKey);
  if (!raw) {
    return;
  }
  saveIdentity(JSON.parse(raw));
  loadClients().catch((error) => status(error.message, true));
}

function resetIdentity() {
  state.identity = null;
  state.clients = [];
  state.selected = null;
  localStorage.removeItem(storeKey);
  els.clientId.disabled = false;
  els.displayName.disabled = false;
  els.register.disabled = false;
  els.clientId.value = "";
  els.displayName.value = "";
  els.clients.replaceChildren();
  els.messages.replaceChildren();
  els.chatTitle.textContent = "Select a client";
  status("");
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

async function register(identity) {
  const payload = {
    id: identity.clientId,
    display_name: identity.displayName,
    public_key: identity.publicKey,
    encryption_public_key: identity.encryptionPublicKey,
  };
  const response = await fetch("/api/clients", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (response.status === 409) {
    throw new Error("Client ID already exists.");
  }
  return apiJson(response);
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

els.identityForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const clientId = els.clientId.value.trim();
    const displayName = els.displayName.value.trim();
    const identity = await generateIdentity(clientId, displayName);
    const registered = await register(identity);
    identity.identityToken = registered.identity_token;
    saveIdentity(identity);
    await loadClients();
    status("Registered.");
  } catch (error) {
    status(error.message, true);
  }
});

els.newIdentity.addEventListener("click", async () => {
  resetIdentity();
});

els.refreshClients.addEventListener("click", () => {
  loadClients().catch((error) => status(error.message, true));
});
els.refreshMessages.addEventListener("click", () => {
  loadMessages().catch((error) => status(error.message, true));
});
els.messageForm.addEventListener("submit", (event) => {
  sendMessage(event).catch((error) => status(error.message, true));
});

loadIdentity();
