const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KDF_ITERATIONS = 600000;

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function derivePassphraseKey(passphrase, salt, iterations = KDF_ITERATIONS) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function createKeyBundle(passphrase) {
  if (typeof passphrase !== "string" || passphrase.length < 12) {
    throw new Error("Use a recovery passphrase with at least 12 characters.");
  }

  const pair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const privateKeyBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const wrappingKey = await derivePassphraseKey(passphrase, salt);
  const encryptedPrivateKey = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    privateKeyBytes
  );

  return {
    public_key: publicKey,
    encrypted_private_key: toBase64(new Uint8Array(encryptedPrivateKey)),
    private_key_iv: toBase64(iv),
    salt: toBase64(salt),
    kdf_iterations: KDF_ITERATIONS
  };
}

export async function unlockPrivateKey(bundle, passphrase) {
  if (!bundle?.encrypted_private_key || !bundle?.private_key_iv || !bundle?.salt) {
    throw new Error("Your encrypted recovery key is incomplete.");
  }
  const iterations = Number(bundle.kdf_iterations);
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) {
    throw new Error("The recovery key settings are invalid.");
  }
  const wrappingKey = await derivePassphraseKey(passphrase, fromBase64(bundle.salt), iterations);
  let privateKeyBytes;
  try {
    privateKeyBytes = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(bundle.private_key_iv) },
      wrappingKey,
      fromBase64(bundle.encrypted_private_key)
    );
  } catch {
    throw new Error("That recovery passphrase is incorrect.");
  }
  return crypto.subtle.importKey(
    "pkcs8",
    privateKeyBytes,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );
}

export async function encryptMessage(plaintext, conversationId, recipients) {
  if (!Array.isArray(recipients) || recipients.length < 2) {
    throw new Error("Encryption keys for every conversation participant are required.");
  }
  const contentKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const rawContentKey = await crypto.subtle.exportKey("raw", contentKey);
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(conversationId) },
    contentKey,
    encoder.encode(plaintext)
  );
  const wrappedKeys = {};
  for (const recipient of recipients) {
    if (!recipient?.id || !recipient?.public_key) {
      throw new Error("A conversation participant has not finished encryption setup.");
    }
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      recipient.public_key,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );
    const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawContentKey);
    wrappedKeys[String(recipient.id)] = toBase64(new Uint8Array(wrapped));
  }
  return JSON.stringify({
    version: 1,
    algorithm: "RSA-OAEP-256+A256GCM",
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
    wrapped_keys: wrappedKeys
  });
}

export async function decryptMessage(serializedEnvelope, conversationId, userId, privateKey) {
  let envelope;
  try {
    envelope = typeof serializedEnvelope === "string" ? JSON.parse(serializedEnvelope) : serializedEnvelope;
  } catch {
    throw new Error("This encrypted message is damaged.");
  }
  if (envelope?.version !== 1 || envelope?.algorithm !== "RSA-OAEP-256+A256GCM") {
    throw new Error("This message uses an unsupported encryption format.");
  }
  const wrappedKey = envelope.wrapped_keys?.[String(userId)];
  if (!wrappedKey) throw new Error("This message was not encrypted for this account.");
  const rawContentKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    fromBase64(wrappedKey)
  );
  const contentKey = await crypto.subtle.importKey(
    "raw",
    rawContentKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(envelope.iv), additionalData: encoder.encode(conversationId) },
    contentKey,
    fromBase64(envelope.ciphertext)
  );
  return decoder.decode(plaintext);
}
