import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createKeyBundle, unlockPrivateKey, encryptMessage, decryptMessage } from "./crypto.js";
import {
  ArrowLeft,
  ArrowUpRight,
  Check,
  LockKeyhole,
  LogOut,
  MessageCircle,
  MoreHorizontal,
  Plus,
  Search,
  Send,
  ShieldCheck,
  UserRound,
  Users,
  X
} from "lucide-react";

const ACCOUNTS = "https://accounts.theegget.com";
const CLIENT_ID = import.meta.env.VITE_TC_OAUTH_CLIENT_ID || "";
const CALLBACK = `${window.location.origin}/auth/callback`;
const TOKEN_KEY = "tcchat_access_token";

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomString(length = 64) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

async function createChallenge(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

async function exchangeCode(code) {
  const verifier = sessionStorage.getItem("tcchat_code_verifier");
  const expectedState = sessionStorage.getItem("tcchat_oauth_state");
  const params = new URLSearchParams(window.location.search);
  const returnedState = params.get("state");

  if (!verifier || !expectedState || returnedState !== expectedState) {
    throw new Error("The sign-in verification did not match. Start sign-in again.");
  }

  const response = await fetch(`${ACCOUNTS}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      redirect_uri: CALLBACK,
      code_verifier: verifier
    })
  });
  const data = await response.json();
  if (!response.ok || !data.access_token) {
    throw new Error(data.error_description || data.error || "TC Accounts could not complete sign-in.");
  }

  sessionStorage.removeItem("tcchat_code_verifier");
  sessionStorage.removeItem("tcchat_oauth_state");
  sessionStorage.setItem(TOKEN_KEY, data.access_token);
  window.history.replaceState({}, "", "/");
  return data.access_token;
}

async function startSignIn() {
  if (!CLIENT_ID) throw new Error("TC Chat is not connected to a TC Accounts OAuth application yet.");
  const verifier = randomString(64);
  const state = randomString(32);
  const challenge = await createChallenge(verifier);
  sessionStorage.setItem("tcchat_code_verifier", verifier);
  sessionStorage.setItem("tcchat_oauth_state", state);

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: CALLBACK,
    response_type: "code",
    scope: "profile",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });
  window.location.assign(`${ACCOUNTS}/oauth/authorize?${params.toString()}`);
}

function initials(name = "?") {
  return name.slice(0, 2).toUpperCase();
}

function timeLabel(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const today = new Date();
  if (date.toDateString() === today.toDateString()) {
    return date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }
  return date.toLocaleDateString([], { month: "short", day: "numeric" });
}

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem(TOKEN_KEY) || "");
  const [user, setUser] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [activeId, setActiveId] = useState("");
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");
  const [modal, setModal] = useState(false);
  const [search, setSearch] = useState("");
  const [directory, setDirectory] = useState([]);
  const [selectedUsers, setSelectedUsers] = useState([]);
  const [groupTitle, setGroupTitle] = useState("");
  const [creating, setCreating] = useState(false);
  const [mobileChat, setMobileChat] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [keyBundle, setKeyBundle] = useState(null);
  const [privateKey, setPrivateKey] = useState(null);
  const [keyPassphrase, setKeyPassphrase] = useState("");
  const [keyConfirm, setKeyConfirm] = useState("");
  const [keyError, setKeyError] = useState("");
  const [keyLoading, setKeyLoading] = useState(false);
  const [keyStatusLoading, setKeyStatusLoading] = useState(false);
  const bottomRef = useRef(null);
  const migrationInProgressRef = useRef(new Set());
  const migrationCompletedRef = useRef(new Set());
  const activeConversation = conversations.find(item => item.id === activeId);

  const api = useCallback(async (path, options = {}) => {
    const response = await fetch(path, {
      ...options,
      headers: {
        ...(options.body ? { "content-type": "application/json" } : {}),
        authorization: `Bearer ${token}`,
        ...options.headers
      }
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const problem = new Error(data.message || data.error || "The request could not be completed.");
      problem.code = data.error;
      problem.status = response.status;
      throw problem;
    }
    return data;
  }, [token]);

  const loadConversations = useCallback(async (quiet = false) => {
    try {
      const data = await api("/api/conversations");
      setConversations(data.conversations || []);
      setError("");
    } catch (problem) {
      if (!quiet) setError(problem.message);
      if (problem.status === 401) {
        sessionStorage.removeItem(TOKEN_KEY);
        setToken("");
      }
    }
  }, [api]);

  const loadMessages = useCallback(async (conversationId, quiet = false) => {
    if (!conversationId || !privateKey || !user) return;
    if (migrationInProgressRef.current.has(conversationId)) return;
    try {
      let data = await api(`/api/conversations/${conversationId}/messages?limit=80`);
      let migrationWarning = "";
      if (!migrationCompletedRef.current.has(conversationId)) {
        migrationInProgressRef.current.add(conversationId);
        try {
          const conversation = conversations.find(item => String(item.id) === String(conversationId));
          const participantIds = [...new Set((conversation?.participants || []).map(person => String(person.id)))];
          if (participantIds.length >= 2) {
            const keyData = await api(`/api/keys?user_ids=${encodeURIComponent(participantIds.join(","))}`);
            if ((keyData.keys || []).length !== participantIds.length) {
              migrationWarning = "Some older messages are still stored as plaintext because every participant must finish encryption setup.";
            } else {
              let page = data.messages || [];
              while (page.length) {
                for (const message of page) {
                  if (message.encrypted_payload || typeof message.body !== "string") continue;
                  const encryptedPayload = await encryptMessage(message.body, conversationId, keyData.keys);
                  await api(`/api/conversations/${conversationId}/messages/${message.id}/encrypt`, {
                    method: "POST",
                    body: JSON.stringify({ encrypted_payload: encryptedPayload })
                  });
                }
                if (page.length < 80) break;
                const oldest = page[0]?.created_at;
                if (!oldest) break;
                const older = await api(`/api/conversations/${conversationId}/messages?limit=80&before=${encodeURIComponent(oldest)}`);
                page = older.messages || [];
              }
              migrationCompletedRef.current.add(conversationId);
              data = await api(`/api/conversations/${conversationId}/messages?limit=80`);
            }
          } else {
            migrationWarning = "Older messages could not be encrypted because the conversation participants could not be verified.";
          }
        } finally {
          migrationInProgressRef.current.delete(conversationId);
        }
      }
      const decrypted = await Promise.all((data.messages || []).map(async message => {
        if (!message.encrypted_payload) return { ...message, legacy_plaintext: true };
        try {
          const body = await decryptMessage(message.encrypted_payload, conversationId, user.id, privateKey);
          return { ...message, body, encrypted: true };
        } catch {
          return { ...message, body: "Unable to decrypt this message on this device.", encrypted: true, decryption_error: true };
        }
      }));
      setMessages(decrypted);
      setError(migrationWarning);
    } catch (problem) {
      migrationInProgressRef.current.delete(conversationId);
      if (!quiet) setError(problem.message);
      if (problem.status === 401) {
        sessionStorage.removeItem(TOKEN_KEY);
        setToken("");
      }
    }
  }, [api, privateKey, user, conversations]);

  useEffect(() => {
    let cancelled = false;
    async function initialize() {
      try {
        const params = new URLSearchParams(window.location.search);
        if (params.has("error")) throw new Error(params.get("error_description") || params.get("error"));
        let currentToken = token;
        if (params.has("code")) {
          currentToken = await exchangeCode(params.get("code"));
          if (!cancelled) setToken(currentToken);
        }
        if (!currentToken) {
          setLoading(false);
          return;
        }
        const response = await fetch("/api/me", {
          headers: { authorization: `Bearer ${currentToken}` }
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          const problem = new Error(data.message || "Your TC sign-in could not be verified.");
          problem.code = data.error;
          throw problem;
        }
        if (!cancelled) {
          setUser(data.user);
          sessionStorage.setItem(TOKEN_KEY, currentToken);
        }
      } catch (problem) {
        if (!cancelled) {
          setError(problem.message);
          if (problem.code === "invalid_session" || problem.code === "not_authenticated") {
            sessionStorage.removeItem(TOKEN_KEY);
            setToken("");
          }
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    initialize();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!user || !token) return;
    let cancelled = false;
    setKeyStatusLoading(true);
    api("/api/keys/self").then(data => {
      if (!cancelled) {
        const pending = sessionStorage.getItem("tcchat_pending_key_bundle");
        setKeyBundle(data.key_bundle || (pending ? { ...JSON.parse(pending), _pendingRegistration: true } : null));
      }
    }).catch(problem => {
      if (!cancelled) setKeyError(problem.message);
    }).finally(() => {
      if (!cancelled) setKeyStatusLoading(false);
    });
    return () => { cancelled = true; };
  }, [user, token, api]);

  async function activateEncryption() {
    if (keyLoading || !keyPassphrase) return;
    setKeyLoading(true);
    setKeyError("");
    try {
      let bundle = keyBundle;
      if (!bundle) {
        if (keyPassphrase.length < 12) throw new Error("Use a recovery passphrase with at least 12 characters.");
        if (keyPassphrase !== keyConfirm) throw new Error("The recovery passphrases do not match.");
        bundle = await createKeyBundle(keyPassphrase);
        sessionStorage.setItem("tcchat_pending_key_bundle", JSON.stringify(bundle));
        setKeyBundle({ ...bundle, _pendingRegistration: true });
      }
      if (bundle._pendingRegistration) {
        const { _pendingRegistration, ...registrationBundle } = bundle;
        await api("/api/keys/self", { method: "POST", body: JSON.stringify(registrationBundle) });
        sessionStorage.removeItem("tcchat_pending_key_bundle");
        bundle = registrationBundle;
        setKeyBundle(bundle);
      }
      const unlocked = await unlockPrivateKey(bundle, keyPassphrase);
      setPrivateKey(unlocked);
      setKeyPassphrase("");
      setKeyConfirm("");
    } catch (problem) {
      setKeyError(problem.message);
    } finally {
      setKeyLoading(false);
    }
  }

  function lockEncryption() {
    setPrivateKey(null);
    setKeyPassphrase("");
    setKeyConfirm("");
    setMessages([]);
    setActiveId("");
    setConversations([]);
  }

  useEffect(() => {
    if (!user || !token || !privateKey) return;
    loadConversations();
    const interval = window.setInterval(() => loadConversations(true), 10000);
    return () => window.clearInterval(interval);
  }, [user, token, privateKey, loadConversations]);

  useEffect(() => {
    if (!activeId || !token || !privateKey) return;
    loadMessages(activeId);
    const interval = window.setInterval(() => loadMessages(activeId, true), 3500);
    return () => window.clearInterval(interval);
  }, [activeId, token, privateKey, loadMessages]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  useEffect(() => {
    if (!modal || search.trim().length < 2) {
      setDirectory([]);
      return;
    }
    let cancelled = false;
    const timeout = window.setTimeout(async () => {
      try {
        const data = await api(`/api/directory?q=${encodeURIComponent(search.trim())}`);
        if (!cancelled) setDirectory(data.users || []);
      } catch (problem) {
        if (!cancelled) setError(problem.message);
      }
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [search, modal, api]);

  const conversationName = useCallback((conversation) => {
    if (!conversation) return "Conversation";
    if (conversation.type === "group") return conversation.title || conversation.participants?.filter(person => String(person.id) !== String(user?.id)).map(person => person.username).join(", ") || "Group chat";
    return conversation.participants?.find(person => String(person.id) !== String(user?.id))?.username || "TC user";
  }, [user]);

  const activePeople = useMemo(() => activeConversation?.participants || [], [activeConversation]);

  async function sendMessage(event) {
    event.preventDefault();
    const body = draft.trim();
    if (!body || !activeId || sending) return;
    setSending(true);
    setDraft("");
    try {
      const participantIds = activePeople.map(person => String(person.id));
      const keyData = await api(`/api/keys?user_ids=${encodeURIComponent(participantIds.join(","))}`);
      if ((keyData.keys || []).length !== participantIds.length) {
        throw new Error("Every participant must finish encryption setup before messages can be sent.");
      }
      const encryptedPayload = await encryptMessage(body, activeId, keyData.keys);
      await api(`/api/conversations/${activeId}/messages`, {
        method: "POST",
        body: JSON.stringify({ encrypted_payload: encryptedPayload })
      });
      await Promise.all([loadMessages(activeId, true), loadConversations(true)]);
    } catch (problem) {
      setDraft(body);
      setError(problem.message);
    } finally {
      setSending(false);
    }
  }

  function toggleSelected(personId) {
    setSelectedUsers(current => current.includes(personId)
      ? current.filter(id => id !== personId)
      : [...current, personId]);
  }

  async function createConversation() {
    if (!selectedUsers.length || creating) return;
    setCreating(true);
    try {
      const participantIds = [...new Set([String(user.id), ...selectedUsers.map(String)])];
      const keyData = await api(`/api/keys?user_ids=${encodeURIComponent(participantIds.join(","))}`);
      if ((keyData.keys || []).length !== participantIds.length) {
        throw new Error("Every selected user must finish encryption setup before joining a conversation.");
      }
      const data = await api("/api/conversations", {
        method: "POST",
        body: JSON.stringify({
          participant_ids: selectedUsers,
          title: selectedUsers.length > 1 ? groupTitle.trim() : null
        })
      });
      await loadConversations(true);
      setActiveId(data.conversation_id);
      setMobileChat(true);
      setModal(false);
      setSearch("");
      setSelectedUsers([]);
      setGroupTitle("");
      await loadMessages(data.conversation_id, true);
    } catch (problem) {
      setError(problem.message);
    } finally {
      setCreating(false);
    }
  }

  async function blockActiveUser() {
    const person = activePeople.find(item => String(item.id) !== String(user?.id));
    if (!person) return;
    if (!window.confirm(`Block ${person.username}? They will no longer be able to start or continue conversations with you.`)) return;
    try {
      await api(`/api/users/${person.id}/block`, { method: "POST" });
      setMenuOpen(false);
      setActiveId("");
      setMessages([]);
      await loadConversations(true);
    } catch (problem) {
      setError(problem.message);
    }
  }

  function signOut() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem("tcchat_code_verifier");
    sessionStorage.removeItem("tcchat_oauth_state");
    setToken("");
    setUser(null);
    setKeyBundle(null);
    setPrivateKey(null);
    sessionStorage.removeItem("tcchat_pending_key_bundle");
    setConversations([]);
    setMessages([]);
    setActiveId("");
  }

  if (loading) {
    return <main className="loading-screen"><div className="brand-mark"><MessageCircle size={22} /></div><span>Connecting to TC Accounts…</span></main>;
  }

  if (user && keyStatusLoading) {
    return <main className="loading-screen"><div className="brand-mark"><LockKeyhole size={22} /></div><span>Checking encryption recovery…</span></main>;
  }

  if (user && !privateKey) {
    return (
      <main className="auth-screen">
        <section className="auth-card">
          <div className="brand-mark"><LockKeyhole size={25} /></div>
          <p className="eyebrow">TC CHAT SECURITY</p>
          <h1>{keyBundle ? "Unlock your messages" : "Set up encryption"}</h1>
          <p className="auth-copy">{keyBundle ? "Enter your recovery passphrase to unlock your encrypted message history on this device." : "Create a recovery passphrase. It encrypts your private key so you can restore message access on another device. TC Chat never receives this passphrase."}</p>
          {keyError && <div className="notice error-notice">{keyError}</div>}
          <label className="key-input-label">Recovery passphrase<input type="password" autoComplete="new-password" value={keyPassphrase} onChange={event => setKeyPassphrase(event.target.value)} placeholder="At least 12 characters" /></label>
          {!keyBundle && <label className="key-input-label">Confirm recovery passphrase<input type="password" autoComplete="new-password" value={keyConfirm} onChange={event => setKeyConfirm(event.target.value)} placeholder="Enter it again" /></label>}
          <button className="primary-button sign-in-button" disabled={keyLoading || !keyPassphrase || (!keyBundle && !keyConfirm)} onClick={activateEncryption}>{keyLoading ? "Securing your account…" : keyBundle ? "Unlock TC Chat" : "Create encryption keys"}</button>
          <div className="auth-foot"><LockKeyhole size={14} /> Keep this passphrase safe. It cannot be reset by TC support.</div>
          <button className="key-signout" onClick={signOut}>Sign out</button>
        </section>
      </main>
    );
  }

  if (!user) {
    return (
      <main className="auth-screen">
        <section className="auth-card">
          <div className="brand-mark"><MessageCircle size={25} /></div>
          <p className="eyebrow">THEEGGET CREATIONS</p>
          <h1>TC Chat</h1>
          <p className="auth-copy">Messaging for everyone with a TC Account. Sign in to continue.</p>
          {error && <div className="notice error-notice">{error}</div>}
          <button className="primary-button sign-in-button" onClick={() => startSignIn().catch(problem => setError(problem.message))}>
            Continue with TC Accounts <ArrowUpRight size={17} />
          </button>
          <div className="auth-foot"><LockKeyhole size={14} /> Your TC Account credentials stay with TC Accounts.</div>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <aside className={`sidebar ${mobileChat ? "sidebar-hidden-mobile" : ""}`}>
        <div className="sidebar-top">
          <div className="brand-lockup">
            <div className="brand-mark small-mark"><MessageCircle size={19} /></div>
            <div><strong>TC Chat</strong><span>THEEGGET CREATIONS</span></div>
          </div>
          <button className="icon-button new-chat-button" aria-label="New conversation" onClick={() => setModal(true)}><Plus size={19} /></button>
        </div>

        <div className="service-banner">
          <div className="service-icon"><Users size={18} /></div>
          <div><strong>TC Chat</strong><span>TC community messaging</span></div>
          <span className="service-dot" />
        </div>

        <div className="section-heading"><span>MESSAGES</span><button onClick={() => setModal(true)} aria-label="Start a conversation"><Plus size={15} /></button></div>
        <div className="conversation-list">
          {conversations.length === 0 ? (
            <div className="empty-list"><MessageCircle size={22} /><span>No conversations yet</span><button onClick={() => setModal(true)}>Start a chat</button></div>
          ) : conversations.map(conversation => {
            const name = conversationName(conversation);
            return (
              <button key={conversation.id} className={`conversation-item ${activeId === conversation.id ? "active" : ""}`} onClick={() => { setActiveId(conversation.id); setMobileChat(true); }}>
                <div className={`avatar ${conversation.type === "group" ? "group-avatar" : ""}`}>{conversation.type === "group" ? <Users size={18} /> : initials(name)}</div>
                <div className="conversation-copy">
                  <div className="conversation-title"><strong>{name}</strong><time>{timeLabel(conversation.last_message_at || conversation.updated_at)}</time></div>
                  <p>{conversation.last_message || (conversation.type === "group" ? "Group conversation" : "Start the conversation")}</p>
                </div>
              </button>
            );
          })}
        </div>

        <div className="sidebar-bottom">
          <div className="account-chip">
            <div className="avatar account-avatar">{initials(user.username)}</div>
            <div className="account-copy"><strong>{user.username}</strong><span>TC Account · Encrypted</span></div>
            <button className="icon-button" onClick={lockEncryption} aria-label="Lock encrypted messages" title="Lock encrypted messages"><LockKeyhole size={17} /></button><button className="icon-button" onClick={signOut} aria-label="Sign out" title="Sign out"><LogOut size={17} /></button>
          </div>
        </div>
      </aside>

      <section className={`chat-panel ${mobileChat ? "chat-panel-mobile" : ""}`}>
        {error && <div className="toast-error"><span>{error}</span><button onClick={() => setError("")}><X size={15} /></button></div>}
        {!activeConversation ? (
          <div className="welcome-panel">
            <div className="welcome-icon"><MessageCircle size={30} /></div>
            <h2>Your conversations</h2>
            <p>Message other active TC Accounts.</p>
            <button className="primary-button" onClick={() => setModal(true)}><Plus size={17} /> New conversation</button>
            <div className="privacy-line"><LockKeyhole size={14} /> Private conversations in TC Chat</div>
          </div>
        ) : (
          <>
            <header className="chat-header">
              <button className="icon-button back-button" onClick={() => setMobileChat(false)} aria-label="Back to conversations"><ArrowLeft size={19} /></button>
              <div className="avatar header-avatar">{activeConversation.type === "group" ? <Users size={18} /> : initials(conversationName(activeConversation))}</div>
              <div className="header-copy">
                <strong>{conversationName(activeConversation)}</strong>
                <span>{activeConversation.type === "group" ? `${activePeople.length} participants` : "TC Account"}</span>
              </div>
              <div className="header-actions">
                <button className="icon-button" onClick={() => setMenuOpen(value => !value)} aria-label="Conversation options"><MoreHorizontal size={20} /></button>
                {menuOpen && <div className="action-menu"><button onClick={blockActiveUser}><ShieldCheck size={15} /> Block user</button></div>}
              </div>
            </header>

            <div className="message-stream">
              <div className="conversation-intro">
                <div className="avatar intro-avatar">{activeConversation.type === "group" ? <Users size={22} /> : initials(conversationName(activeConversation))}</div>
                <h3>{conversationName(activeConversation)}</h3>
                <p>{activeConversation.type === "group" ? "This is the beginning of your group conversation." : "This is the beginning of your conversation."}</p>
                <span><LockKeyhole size={12} /> TC Chat</span>
              </div>
              {messages.map((message, index) => {
                const mine = message.sender_id === user.id;
                const previous = messages[index - 1];
                const showName = !mine && (!previous || previous.sender_id !== message.sender_id);
                return (
                  <div key={message.id} className={`message-row ${mine ? "mine" : ""}`}>
                    {!mine && <div className="message-avatar">{initials(message.sender_username)}</div>}
                    <div className="message-content">
                      {showName && <span className="sender-name">{message.sender_username}</span>}
                      <div className="message-bubble">{message.body}</div>{message.legacy_plaintext && <div className="message-meta">Sent before client-side encryption was enabled</div>}{message.decryption_error && <div className="message-meta">Encrypted message could not be opened</div>}
                      <div className="message-meta"><time>{timeLabel(message.created_at)}</time>{mine && <Check size={13} />}</div>
                    </div>
                  </div>
                );
              })}
              <div ref={bottomRef} />
            </div>

            <form className="composer" onSubmit={sendMessage}>
              <div className="composer-inner">
                <input value={draft} onChange={event => setDraft(event.target.value)} placeholder={`Message ${conversationName(activeConversation)}`} maxLength={4000} aria-label="Message" />
                <span className="composer-hint">Enter to send</span>
                <button className="send-button" type="submit" disabled={!draft.trim() || sending} aria-label="Send message">{sending ? <Check size={18} /> : <Send size={18} />}</button>
              </div>
            </form>
          </>
        )}
      </section>

      {modal && (
        <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) setModal(false); }}>
          <section className="new-chat-modal">
            <header><div><h2>New conversation</h2><p>Find anyone with an active TC Account.</p></div><button className="icon-button" onClick={() => setModal(false)} aria-label="Close"><X size={19} /></button></header>
            <label className="search-field"><Search size={18} /><input autoFocus value={search} onChange={event => setSearch(event.target.value)} placeholder="Search TC usernames" /></label>
            {selectedUsers.length > 1 && <input className="group-title-input" value={groupTitle} onChange={event => setGroupTitle(event.target.value)} placeholder="Group name (optional)" maxLength={80} />}
            <div className="directory-results">
              {search.trim().length < 2 ? <div className="directory-hint"><UserRound size={21} /><span>Enter at least 2 characters to find TC users.</span></div> :
                directory.length === 0 ? <div className="directory-hint">No matching TC users found.</div> :
                directory.map(person => (
                  <button key={person.id} className={`directory-person ${selectedUsers.includes(person.id) ? "selected" : ""}`} onClick={() => toggleSelected(person.id)}>
                    <div className="avatar">{initials(person.username)}</div>
                    <strong>{person.username}</strong>
                    <span className="selection-check">{selectedUsers.includes(person.id) ? <Check size={16} /> : <Plus size={16} />}</span>
                  </button>
                ))}
            </div>
            <footer><span>{selectedUsers.length ? `${selectedUsers.length} selected` : "Select one or more users"}</span><button className="primary-button" disabled={!selectedUsers.length || creating} onClick={createConversation}>{creating ? "Creating…" : "Continue"}</button></footer>
          </section>
        </div>
      )}
    </main>
  );
}

export default App;