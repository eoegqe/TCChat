const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    ...headers
  }
});

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID().replaceAll("-", "");
const fail = (code, message, status) => json({ error: code, message }, status);

async function authenticate(request, env) {
  const authorization = request.headers.get("authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
  if (!token || token.length > 4096) return { error: fail("not_authenticated", "Sign in with your TC Account to continue.", 401) };

  let response;
  try {
    response = await fetch(new URL("/oauth/userinfo", env.TC_ACCOUNTS_ORIGIN || "https://accounts.theegget.com"), {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      cf: { cacheTtl: 0 }
    });
  } catch {
    return { error: fail("identity_unavailable", "TC Accounts could not be reached. Try again shortly.", 503) };
  }

  if (!response.ok) return { error: fail("invalid_session", "Your TC sign-in has expired. Sign in again.", 401) };
  let identity;
  try {
    identity = await response.json();
  } catch {
    return { error: fail("identity_unavailable", "TC Accounts returned an invalid response.", 503) };
  }

  if (!identity?.sub || !identity?.preferred_username) {
    return { error: fail("invalid_identity", "TC Accounts did not return a valid account identity.", 401) };
  }

  return {
    user: {
      id: String(identity.sub),
      username: String(identity.preferred_username)
    }
  };
}

async function requireParticipant(env, conversationId, userId) {
  return env.TC.prepare(
    "SELECT c.id, c.type, c.title, c.service_tag FROM tc_chat_conversations c JOIN tc_chat_participants p ON p.conversation_id = c.id WHERE c.id = ? AND p.user_id = ? LIMIT 1"
  ).bind(conversationId, userId).first();
}

async function blockedEitherWay(env, userA, userB) {
  return env.TC.prepare(
    "SELECT 1 AS blocked FROM tc_chat_blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?) LIMIT 1"
  ).bind(userA, userB, userB, userA).first();
}

async function api(request, env, url) {
  const auth = await authenticate(request, env);
  if (auth.error) return auth.error;
  const user = auth.user;
  const path = url.pathname;
  const method = request.method;

  if (path === "/api/me" && method === "GET") {
    return json({ user, service: { tag: "TC", label: "TC Chat" } });
  }

  if (path === "/api/keys/self" && method === "GET") {
    const bundle = await env.TC.prepare("SELECT public_key_jwk, encrypted_private_key, private_key_iv, salt, kdf_iterations FROM tc_chat_user_keys WHERE user_id = ?").bind(user.id).first();
    return json({ key_bundle: bundle ? { public_key: JSON.parse(bundle.public_key_jwk), encrypted_private_key: bundle.encrypted_private_key, private_key_iv: bundle.private_key_iv, salt: bundle.salt, kdf_iterations: bundle.kdf_iterations } : null });
  }

  if (path === "/api/keys/self" && method === "POST") {
    let body;
    try { body = await request.json(); } catch { return fail("invalid_json", "The request body must be valid JSON.", 400); }
    const publicKey = body?.public_key;
    const encryptedPrivateKey = typeof body?.encrypted_private_key === "string" ? body.encrypted_private_key : "";
    const privateKeyIv = typeof body?.private_key_iv === "string" ? body.private_key_iv : "";
    const salt = typeof body?.salt === "string" ? body.salt : "";
    const iterations = Number(body?.kdf_iterations);
    if (publicKey?.kty !== "RSA" || typeof publicKey.n !== "string" || publicKey.n.length < 500 || publicKey.n.length > 600 || publicKey.e !== "AQAB" || publicKey.alg !== "RSA-OAEP-256" || encryptedPrivateKey.length < 100 || encryptedPrivateKey.length > 10000 || !/^[A-Za-z0-9+/]+=*$/.test(encryptedPrivateKey) || !/^[A-Za-z0-9+/]{16}$/.test(privateKeyIv) || !/^[A-Za-z0-9+/]{22}==$/.test(salt) || !Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) return fail("invalid_key_bundle", "The encryption recovery bundle is invalid.", 400);
    const existing = await env.TC.prepare("SELECT user_id FROM tc_chat_user_keys WHERE user_id = ?").bind(user.id).first();
    if (existing) return fail("key_bundle_exists", "An encryption recovery key is already registered for this account.", 409);
    const timestamp = now();
    await env.TC.prepare("INSERT INTO tc_chat_user_keys (user_id, public_key_jwk, encrypted_private_key, private_key_iv, salt, kdf_iterations, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(user.id, JSON.stringify(publicKey), encryptedPrivateKey, privateKeyIv, salt, iterations, timestamp, timestamp).run();
    return json({ success: true }, 201);
  }

  if (path === "/api/keys" && method === "GET") {
    const requested = [...new Set((url.searchParams.get("user_ids") || "").split(",").map(value => value.trim()).filter(Boolean))];
    if (!requested.length || requested.length > 10 || requested.some(value => value.length > 128)) return fail("invalid_key_request", "Request encryption keys for 1 to 10 TC users.", 400);
    const placeholders = requested.map(() => "?").join(",");
    const result = await env.TC.prepare("SELECT k.user_id AS id, k.public_key_jwk FROM tc_chat_user_keys k JOIN users u ON u.id = k.user_id WHERE u.status = 'active' AND k.user_id IN (" + placeholders + ")").bind(...requested).all();
    return json({ keys: (result.results || []).map(item => ({ id: item.id, public_key: JSON.parse(item.public_key_jwk) })) });
  }
  if (path === "/api/directory" && method === "GET") {
    const query = (url.searchParams.get("q") || "").trim().slice(0, 32);
    if (query.length < 2) return json({ users: [] });
    const result = await env.TC.prepare(
      "SELECT u.id, u.username FROM users u WHERE u.status = 'active' AND u.id <> ? AND u.username LIKE ? COLLATE NOCASE AND NOT EXISTS (SELECT 1 FROM tc_chat_blocks b WHERE (b.blocker_id = ? AND b.blocked_id = u.id) OR (b.blocker_id = u.id AND b.blocked_id = ?)) ORDER BY u.username COLLATE NOCASE LIMIT 25"
    ).bind(user.id, `%${query}%`, user.id, user.id).all();
    return json({ users: result.results || [] });
  }

  if (path === "/api/conversations" && method === "GET") {
    const result = await env.TC.prepare(
      "SELECT c.id, c.type, c.title, c.created_at, c.updated_at, (SELECT CASE WHEN m.encrypted_payload IS NOT NULL THEN 'Encrypted message' ELSE m.body END FROM tc_chat_messages m WHERE m.conversation_id = c.id AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT 1) AS last_message, (SELECT m.created_at FROM tc_chat_messages m WHERE m.conversation_id = c.id AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT 1) AS last_message_at, (SELECT COUNT(*) FROM tc_chat_participants p2 WHERE p2.conversation_id = c.id) AS participant_count FROM tc_chat_conversations c JOIN tc_chat_participants p ON p.conversation_id = c.id WHERE p.user_id = ? ORDER BY COALESCE(last_message_at, c.updated_at) DESC LIMIT 100"
    ).bind(user.id).all();

    const conversations = result.results || [];
    for (const conversation of conversations) {
      const people = await env.TC.prepare(
        "SELECT u.id, u.username FROM tc_chat_participants p JOIN users u ON u.id = p.user_id WHERE p.conversation_id = ? ORDER BY u.username COLLATE NOCASE"
      ).bind(conversation.id).all();
      conversation.participants = people.results || [];
    }
    return json({ conversations });
  }

  if (path === "/api/conversations" && method === "POST") {
    let body;
    try { body = await request.json(); } catch { return fail("invalid_json", "The request body must be valid JSON.", 400); }
    const requested = Array.isArray(body?.participant_ids) ? body.participant_ids.map(String) : [];
    const participantIds = [...new Set([user.id, ...requested])];
    if (participantIds.length < 2 || participantIds.length > 10) {
      return fail("invalid_participants", "A conversation must include 2 to 10 TC users.", 400);
    }
    if (participantIds.some(value => value.length > 128)) return fail("invalid_participants", "A participant ID is invalid.", 400);

    const placeholders = participantIds.map(() => "?").join(",");
    const eligible = await env.TC.prepare(
      `SELECT id FROM users WHERE id IN (${placeholders}) AND status = 'active'`
    ).bind(...participantIds).all();
    if ((eligible.results || []).length !== participantIds.length) {
      return fail("participant_unavailable", "Every participant must have an active TC Account.", 404);
    }

    const keyPlaceholders = participantIds.map(() => "?").join(",");
    const registeredKeys = await env.TC.prepare(
      "SELECT user_id FROM tc_chat_user_keys WHERE user_id IN (" + keyPlaceholders + ")"
    ).bind(...participantIds).all();
    if ((registeredKeys.results || []).length !== participantIds.length) {
      return fail("encryption_setup_required", "Every participant must complete encryption setup before starting a conversation.", 409);
    }

    for (const otherId of participantIds.filter(value => value !== user.id)) {
      if (await blockedEitherWay(env, user.id, otherId)) {
        return fail("user_unavailable", "This conversation cannot be created because a participant has restricted contact.", 403);
      }
    }

    const type = participantIds.length === 2 ? "direct" : "group";
    if (type === "direct") {
      const existing = await env.TC.prepare(
        "SELECT c.id FROM tc_chat_conversations c JOIN tc_chat_participants p1 ON p1.conversation_id = c.id AND p1.user_id = ? JOIN tc_chat_participants p2 ON p2.conversation_id = c.id AND p2.user_id = ? WHERE c.type = 'direct' LIMIT 1"
      ).bind(participantIds[0], participantIds[1]).first();
      if (existing) return json({ conversation_id: existing.id, existing: true });
    }

    const conversationId = id();
    const timestamp = now();
    const title = type === "group" && typeof body?.title === "string" ? body.title.trim().slice(0, 80) : null;
    await env.TC.prepare(
      "INSERT INTO tc_chat_conversations (id, service_tag, type, title, created_by, created_at, updated_at) VALUES (?, 'TC', ?, ?, ?, ?, ?)"
    ).bind(conversationId, type, title || null, user.id, timestamp, timestamp).run();

    const insert = env.TC.prepare(
      "INSERT INTO tc_chat_participants (conversation_id, user_id, joined_at) VALUES (?, ?, ?)"
    );
    await env.TC.batch(participantIds.map(participantId => insert.bind(conversationId, participantId, timestamp)));
    return json({ conversation_id: conversationId, existing: false }, 201);
  }

  const messageMatch = path.match(/^\/api\/conversations\/([a-f0-9-]+)\/messages$/i);
  if (messageMatch && method === "GET") {
    const conversationId = messageMatch[1];
    const conversation = await requireParticipant(env, conversationId, user.id);
    if (!conversation) return fail("conversation_not_found", "This conversation is unavailable.", 404);
    const before = url.searchParams.get("before");
    const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 50), 1), 100);
    const result = before
      ? await env.TC.prepare(
          "SELECT m.id, m.sender_id, u.username AS sender_username, m.body, m.encrypted_payload, m.created_at, m.edited_at FROM tc_chat_messages m JOIN users u ON u.id = m.sender_id WHERE m.conversation_id = ? AND m.deleted_at IS NULL AND m.created_at < ? ORDER BY m.created_at DESC LIMIT ?"
        ).bind(conversationId, before, limit).all()
      : await env.TC.prepare(
          "SELECT m.id, m.sender_id, u.username AS sender_username, m.body, m.encrypted_payload, m.created_at, m.edited_at FROM tc_chat_messages m JOIN users u ON u.id = m.sender_id WHERE m.conversation_id = ? AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT ?"
        ).bind(conversationId, limit).all();
    await env.TC.prepare(
      "UPDATE tc_chat_participants SET last_read_at = ? WHERE conversation_id = ? AND user_id = ?"
    ).bind(now(), conversationId, user.id).run();
    return json({ conversation, messages: (result.results || []).reverse() });
  }

  if (messageMatch && method === "POST") {
    const conversationId = messageMatch[1];
    const conversation = await requireParticipant(env, conversationId, user.id);
    if (!conversation) return fail("conversation_not_found", "This conversation is unavailable.", 404);
    let body;
    try { body = await request.json(); } catch { return fail("invalid_json", "The request body must be valid JSON.", 400); }
    const encryptedPayload = typeof body?.encrypted_payload === "string" ? body.encrypted_payload : "";
    if (!encryptedPayload || encryptedPayload.length > 30000) return fail("encrypted_message_required", "Messages must be encrypted on your device before sending.", 400);
    let envelope;
    try { envelope = JSON.parse(encryptedPayload); } catch { return fail("invalid_envelope", "The encrypted message envelope is invalid.", 400); }
    if (envelope?.version !== 1 || envelope?.algorithm !== "RSA-OAEP-256+A256GCM" || typeof envelope.iv !== "string" || typeof envelope.ciphertext !== "string" || !envelope.wrapped_keys || typeof envelope.wrapped_keys !== "object" || Array.isArray(envelope.wrapped_keys)) return fail("invalid_envelope", "The encrypted message envelope is invalid.", 400);
    const participants = await env.TC.prepare("SELECT user_id FROM tc_chat_participants WHERE conversation_id = ?").bind(conversationId).all();
    const participantIds = (participants.results || []).map(item => String(item.user_id));
    const wrappedIds = Object.keys(envelope.wrapped_keys).sort();
    if (participantIds.length < 2 || wrappedIds.length !== participantIds.length || participantIds.some(participantId => typeof envelope.wrapped_keys[participantId] !== "string" || !wrappedIds.includes(participantId))) return fail("missing_recipient_key", "The message must be encrypted for every conversation participant.", 400);
    for (const recipientId of participantIds.filter(value => value !== user.id)) {
      const activeRecipient = await env.TC.prepare("SELECT 1 AS ok FROM users WHERE id = ? AND status = 'active'").bind(recipientId).first();
      if (!activeRecipient || await blockedEitherWay(env, user.id, recipientId)) return fail("recipient_unavailable", "A participant is no longer available for this conversation.", 403);
    }
    const messageId = id();
    const timestamp = now();
    await env.TC.prepare("INSERT INTO tc_chat_messages (id, conversation_id, sender_id, body, encrypted_payload, created_at) VALUES (?, ?, ?, '', ?, ?)").bind(messageId, conversationId, user.id, encryptedPayload, timestamp).run();
    await env.TC.prepare(
      "UPDATE tc_chat_conversations SET updated_at = ? WHERE id = ?"
    ).bind(timestamp, conversationId).run();

    return json({
      message: {
        id: messageId,
        sender_id: user.id,
        sender_username: user.username,
        body: "",
        encrypted_payload: encryptedPayload,
        created_at: timestamp
      }
    }, 201);
  }

  const legacyEncryptMatch = path.match(/^\/api\/conversations\/([a-f0-9-]+)\/messages\/([a-f0-9]+)\/encrypt$/i);
  if (legacyEncryptMatch && method === "POST") {
    const conversationId = legacyEncryptMatch[1];
    const messageId = legacyEncryptMatch[2];
    const conversation = await requireParticipant(env, conversationId, user.id);
    if (!conversation) return fail("conversation_not_found", "This conversation is unavailable.", 404);
    let body;
    try { body = await request.json(); } catch { return fail("invalid_json", "The request body must be valid JSON.", 400); }
    const encryptedPayload = typeof body?.encrypted_payload === "string" ? body.encrypted_payload : "";
    if (!encryptedPayload || encryptedPayload.length > 30000) return fail("invalid_envelope", "The encrypted message envelope is invalid.", 400);
    let envelope;
    try { envelope = JSON.parse(encryptedPayload); } catch { return fail("invalid_envelope", "The encrypted message envelope is invalid.", 400); }
    if (envelope?.version !== 1 || envelope?.algorithm !== "RSA-OAEP-256+A256GCM" || typeof envelope.iv !== "string" || typeof envelope.ciphertext !== "string" || !envelope.wrapped_keys || typeof envelope.wrapped_keys !== "object" || Array.isArray(envelope.wrapped_keys)) return fail("invalid_envelope", "The encrypted message envelope is invalid.", 400);
    const participants = await env.TC.prepare("SELECT user_id FROM tc_chat_participants WHERE conversation_id = ?").bind(conversationId).all();
    const participantIds = (participants.results || []).map(item => String(item.user_id)).sort();
    const wrappedIds = Object.keys(envelope.wrapped_keys).sort();
    if (participantIds.length < 2 || wrappedIds.length !== participantIds.length || participantIds.some(participantId => typeof envelope.wrapped_keys[participantId] !== "string") || wrappedIds.some(participantId => !participantIds.includes(participantId))) return fail("missing_recipient_key", "The historical message must be encrypted for every conversation participant.", 400);
    const result = await env.TC.prepare(
      "UPDATE tc_chat_messages SET encrypted_payload = ?, body = '' WHERE id = ? AND conversation_id = ? AND encrypted_payload IS NULL AND deleted_at IS NULL"
    ).bind(encryptedPayload, messageId, conversationId).run();
    if (!result.meta?.changes) {
      const existing = await env.TC.prepare("SELECT encrypted_payload FROM tc_chat_messages WHERE id = ? AND conversation_id = ? AND deleted_at IS NULL").bind(messageId, conversationId).first();
      if (!existing) return fail("message_not_found", "That message is unavailable.", 404);
      if (existing.encrypted_payload) return json({ success: true, already_encrypted: true });
      return fail("migration_conflict", "The historical message could not be encrypted.", 409);
    }
    return json({ success: true, encrypted: true });
  }

  const blockMatch = path.match(/^\/api\/users\/([a-f0-9-]+)\/block$/i);
  if (blockMatch && method === "POST") {
    const blockedId = blockMatch[1];
    if (blockedId === user.id) return fail("invalid_user", "You cannot block your own account.", 400);
    const target = await env.TC.prepare(
      "SELECT 1 AS ok FROM users WHERE id = ? AND status = 'active'"
    ).bind(blockedId).first();
    if (!target) return fail("user_not_found", "That TC user could not be found.", 404);
    await env.TC.prepare(
      "INSERT OR IGNORE INTO tc_chat_blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)"
    ).bind(user.id, blockedId, now()).run();
    return json({ success: true });
  }

  if (blockMatch && method === "DELETE") {
    await env.TC.prepare(
      "DELETE FROM tc_chat_blocks WHERE blocker_id = ? AND blocked_id = ?"
    ).bind(user.id, blockMatch[1]).run();
    return json({ success: true });
  }

  return fail("not_found", "The requested TC Chat endpoint does not exist.", 404);
}

async function syncMembership(request, env) {
  if (!env.EGGSER_SYNC_SECRET) return fail("sync_not_configured", "Eggser membership sync is not configured.", 503);
  const supplied = request.headers.get("x-tc-sync-secret") || "";
  if (supplied.length !== env.EGGSER_SYNC_SECRET.length) return fail("forbidden", "The sync credential is invalid.", 403);
  const a = new TextEncoder().encode(supplied);
  const b = new TextEncoder().encode(env.EGGSER_SYNC_SECRET);
  const digestA = await crypto.subtle.digest("SHA-256", a);
  const digestB = await crypto.subtle.digest("SHA-256", b);
  const bytesA = new Uint8Array(digestA);
  const bytesB = new Uint8Array(digestB);
  let mismatch = 0;
  for (let i = 0; i < bytesA.length; i++) mismatch |= bytesA[i] ^ bytesB[i];
  if (mismatch !== 0) return fail("forbidden", "The sync credential is invalid.", 403);

  let body;
  try { body = await request.json(); } catch { return fail("invalid_json", "The request body must be valid JSON.", 400); }
  const userId = typeof body?.user_id === "string" ? body.user_id.trim() : "";
  if (!userId || userId.length > 128 || typeof body?.active !== "boolean") {
    return fail("invalid_membership", "Provide a valid user_id and boolean active value.", 400);
  }
  const account = await env.TC.prepare("SELECT id FROM users WHERE id = ? LIMIT 1").bind(userId).first();
  if (!account) return fail("account_not_found", "The TC account does not exist.", 404);
  const timestamp = now();
  await env.TC.prepare(
    "INSERT INTO tc_service_memberships (user_id, service_tag, status, linked_at, updated_at) VALUES (?, 'Eggser', ?, ?, ?) ON CONFLICT(user_id, service_tag) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at"
  ).bind(userId, body.active ? "active" : "revoked", timestamp, timestamp).run();
  return json({ success: true, user_id: userId, service_tag: "Eggser", status: body.active ? "active" : "revoked" });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/internal/")) {
      if (url.pathname === "/internal/services/eggser/membership" && request.method === "POST") {
        return syncMembership(request, env);
      }
      return fail("not_found", "The requested internal endpoint does not exist.", 404);
    }
    if (url.pathname.startsWith("/api/")) {
      try {
        return await api(request, env, url);
      } catch (error) {
        console.error("TC Chat API error:", String(error?.stack || error?.message || error));
        return fail("server_error", "TC Chat could not complete that request. Try again shortly.", 500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};
