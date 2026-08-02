import { attachmentName, state } from "./context.js";
import { b64, bytes, decoder, encoder, sha256Hex } from "./crypto_core.js";

export {
  apiJson,
  b64,
  bundleKey,
  bytes,
  fingerprint,
  sha256Hex,
} from "./crypto_core.js";

export async function signingPrivateKey() {
  return crypto.subtle.importKey(
    "pkcs8",
    bytes(state.identity.signingPrivateKey),
    "Ed25519",
    false,
    ["sign"],
  );
}

export async function encryptionPrivateKey() {
  return crypto.subtle.importKey(
    "pkcs8",
    bytes(state.identity.encryptionPrivateKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey"],
  );
}

export async function encryptionPublicKey(value) {
  return crypto.subtle.importKey(
    "spki",
    bytes(value),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
}

export async function signedFetch(path, options = {}) {
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

export async function encryptFor(recipient, plaintext, metadata = {}) {
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

export async function decryptMessage(message) {
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
