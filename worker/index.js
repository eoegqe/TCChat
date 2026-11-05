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

  const membership = await env.TC.prepare(
    "SELECT status FROM tc_service_memberships WHERE user_id = ? AND service_tag = 'Eggser' LIMIT 1"
  ).bind(String(identity.sub)).first();

  if (!membership || membership.status !== "active") {
    return {
      error: fail(
        "eggser_subaccount_required",
        "TC Chat is available here only to TC accounts with an active Eggser sub-account.",
        403
      )
    };
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
    "SELECT c.id, c.type, c.title, c.service_tag FROM tc_chat_conversations c JOIN tc_chat_participants p ON p.conversation_id = c.id WHERE c.id = ? AND p.user_id = ? AND c.service_tag = 'Eggser' LIMIT 1"
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
    return json({ user, service: { tag: "Eggser", label: "Eggser" } });
  }

  if (path === "/api/directory" && method === "GET") {
    const query = (url.searchParams.get("q") || "").trim().slice(0, 32);
    if (query.length < 2) return json({ users: [] });
    const result = await env.TC.prepare(
      "SELECT u.id, u.username FROM users u JOIN tc_service_memberships sm ON sm.user_id = u.id WHERE sm.service_tag = 'Eggser' AND sm.status = 'active' AND u.status = 'active' AND u.id <> ? AND u.username LIKE ? COLLATE NOCASE AND NOT EXISTS (SELECT 1 FROM tc_chat_blocks b WHERE (b.blocker_id = ? AND b.blocked_id = u.id) OR (b.blocker_id = u.id AND b.blocked_id = ?)) ORDER BY u.username COLLATE NOCASE LIMIT 25"
    ).bind(user.id, `%${query}%`, user.id, user.id).all();
    return json({ users: result.results || [] });
  }

  if (path === "/api/conversations" && method === "GET") {
    const result = await env.TC.prepare(
      "SELECT c.id, c.type, c.title, c.created_at, c.updated_at, (SELECT m.body FROM tc_chat_messages m WHERE m.conversation_id = c.id AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT 1) AS last_message, (SELECT m.created_at FROM tc_chat_messages m WHERE m.conversation_id = c.id AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT 1) AS last_message_at, (SELECT COUNT(*) FROM tc_chat_participants p2 WHERE p2.conversation_id = c.id) AS participant_count FROM tc_chat_conversations c JOIN tc_chat_participants p ON p.conversation_id = c.id WHERE p.user_id = ? AND c.service_tag = 'Eggser' ORDER BY COALESCE(last_message_at, c.updated_at) DESC LIMIT 100"
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
      `SELECT u.id FROM users u JOIN tc_service_memberships sm ON sm.user_id = u.id WHERE u.id IN (${placeholders}) AND u.status = 'active' AND sm.service_tag = 'Eggser' AND sm.status = 'active'`
    ).bind(...participantIds).all();
    if ((eligible.results || []).length !== participantIds.length) {
      return fail("eggser_membership_required", "Every participant must have an active Eggser sub-account.", 403);
    }

    for (const otherId of participantIds.filter(value => value !== user.id)) {
      if (await blockedEitherWay(env, user.id, otherId)) {
        return fail("user_unavailable", "This conversation cannot be created because a participant has restricted contact.", 403);
      }
    }

    const type = participantIds.length === 2 ? "direct" : "group";
    if (type === "direct") {
      const existing = await env.TC.prepare(
        "SELECT c.id FROM tc_chat_conversations c JOIN tc_chat_participants p1 ON p1.conversation_id = c.id AND p1.user_id = ? JOIN tc_chat_participants p2 ON p2.conversation_id = c.id AND p2.user_id = ? WHERE c.type = 'direct' AND c.service_tag = 'Eggser' LIMIT 1"
      ).bind(participantIds[0], participantIds[1]).first();
      if (existing) return json({ conversation_id: existing.id, existing: true });
    }

    const conversationId = id();
    const timestamp = now();
    const title = type === "group" && typeof body?.title === "string" ? body.title.trim().slice(0, 80) : null;
    await env.TC.prepare(
      "INSERT INTO tc_chat_conversations (id, service_tag, type, title, created_by, created_at, updated_at) VALUES (?, 'Eggser', ?, ?, ?, ?, ?)"
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
          "SELECT m.id, m.sender_id, u.username AS sender_username, m.body, m.created_at, m.edited_at FROM tc_chat_messages m JOIN users u ON u.id = m.sender_id WHERE m.conversation_id = ? AND m.deleted_at IS NULL AND m.created_at < ? ORDER BY m.created_at DESC LIMIT ?"
        ).bind(conversationId, before, limit).all()
      : await env.TC.prepare(
          "SELECT m.id, m.sender_id, u.username AS sender_username, m.body, m.created_at, m.edited_at FROM tc_chat_messages m JOIN users u ON u.id = m.sender_id WHERE m.conversation_id = ? AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT ?"
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
    const message = typeof body?.body === "string" ? body.body.trim() : "";
    if (!message) return fail("empty_message", "Write a message before sending.", 400);
    if (message.length > 4000) return fail("message_too_long", "Messages must be 4,000 characters or fewer.", 400);

    const recipients = await env.TC.prepare(
      "SELECT user_id FROM tc_chat_participants WHERE conversation_id = ? AND user_id <> ?"
    ).bind(conversationId, user.id).all();
    for (const recipient of recipients.results || []) {
      const stillEligible = await env.TC.prepare(
        "SELECT 1 AS ok FROM tc_service_memberships WHERE user_id = ? AND service_tag = 'Eggser' AND status = 'active'"
      ).bind(recipient.user_id).first();
      if (!stillEligible || await blockedEitherWay(env, user.id, recipient.user_id)) {
        return fail("recipient_unavailable", "A participant is no longer available for this conversation.", 403);
      }
    }

    const messageId = id();
    const timestamp = now();
    await env.TC.prepare(
      "INSERT INTO tc_chat_messages (id, conversation_id, sender_id, body, created_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(messageId, conversationId, user.id, message, timestamp).run();
    await env.TC.prepare(
      "UPDATE tc_chat_conversations SET updated_at = ? WHERE id = ?"
    ).bind(timestamp, conversationId).run();

    return json({
      message: {
        id: messageId,
        sender_id: user.id,
        sender_username: user.username,
        body: message,
        created_at: timestamp
      }
    }, 201);
  }

  const blockMatch = path.match(/^\/api\/users\/([a-f0-9-]+)\/block$/i);
  if (blockMatch && method === "POST") {
    const blockedId = blockMatch[1];
    if (blockedId === user.id) return fail("invalid_user", "You cannot block your own account.", 400);
    const target = await env.TC.prepare(
      "SELECT 1 AS ok FROM tc_service_memberships WHERE user_id = ? AND service_tag = 'Eggser' AND status = 'active'"
    ).bind(blockedId).first();
    if (!target) return fail("user_not_found", "That Eggser user could not be found.", 404);
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
