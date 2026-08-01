const storeKey = "pasztar.identity";
const pendingKey = "pasztar.pendingIdentity";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const els = {
  identityForm: document.querySelector("#identity-form"),
  clientId: document.querySelector("#client-id"),
  displayName: document.querySelector("#display-name"),
  identityImport: document.querySelector("#identity-import"),
  setupStatus: document.querySelector("#setup-status"),
};

if (localStorage.getItem(storeKey)) {
  location.replace("/");
}

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
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

async function fingerprint(publicKey) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(publicKey));
  return [...new Uint8Array(hash)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function status(text, error = false) {
  els.setupStatus.textContent = text;
  els.setupStatus.classList.toggle("error", error);
}

function requireString(bundle, key) {
  if (typeof bundle[key] !== "string" || !bundle[key].trim()) {
    throw new Error(`Invalid identity bundle: missing ${key}.`);
  }
}

function saveBundle(bundle) {
  for (const key of [
    "clientId",
    "displayName",
    "publicKey",
    "encryptionPublicKey",
    "signingPrivateKey",
    "encryptionPrivateKey",
    "fingerprint",
  ]) {
    requireString(bundle, key);
  }
  localStorage.removeItem(pendingKey);
  localStorage.setItem(storeKey, JSON.stringify(bundle));
  location.replace("/");
}

function loadPendingIdentity(clientId, displayName) {
  try {
    const identity = JSON.parse(localStorage.getItem(pendingKey));
    if (identity?.clientId === clientId && identity?.displayName === displayName) {
      return identity;
    }
  } catch {
    localStorage.removeItem(pendingKey);
  }
  return null;
}

async function decryptBundle(bundle) {
  if (bundle?.type !== "pasztar.identity.encrypted") {
    return bundle;
  }
  const passphrase = prompt("Identity bundle passphrase");
  if (!passphrase) {
    throw new Error("Passphrase is required.");
  }
  try {
    const key = await bundleKey(passphrase, bytes(bundle.salt), ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes(bundle.iv) },
      key,
      bytes(bundle.data),
    );
    return JSON.parse(decoder.decode(plaintext));
  } catch (error) {
    throw new Error("Invalid bundle or passphrase.");
  }
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

async function apiJson(response) {
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(data?.detail || response.statusText);
  }
  return data;
}

async function register(identity) {
  const response = await fetch("/api/clients", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: identity.clientId,
      display_name: identity.displayName,
      public_key: identity.publicKey,
      encryption_public_key: identity.encryptionPublicKey,
    }),
  });
  if (response.status === 409) {
    throw new Error("Client ID already exists.");
  }
  return apiJson(response);
}

els.identityForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const clientId = els.clientId.value.trim();
    const displayName = els.displayName.value.trim();
    const identity =
      loadPendingIdentity(clientId, displayName) ||
      (await generateIdentity(clientId, displayName));
    localStorage.setItem(pendingKey, JSON.stringify(identity));
    await register(identity);
    saveBundle(identity);
  } catch (error) {
    status(error.message, true);
  }
});

els.identityImport.addEventListener("change", async () => {
  try {
    const file = els.identityImport.files[0];
    if (!file) {
      return;
    }
    saveBundle(await decryptBundle(JSON.parse(await file.text())));
  } catch (error) {
    els.identityImport.value = "";
    status(error.message, true);
  }
});
