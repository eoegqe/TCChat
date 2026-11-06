CREATE TABLE IF NOT EXISTS tc_chat_calls (
 id TEXT PRIMARY KEY NOT NULL, conversation_id TEXT NOT NULL, caller_id TEXT NOT NULL, callee_id TEXT NOT NULL,
 media_type TEXT NOT NULL CHECK(media_type IN ('audio','video')),
 status TEXT NOT NULL CHECK(status IN ('ringing','active','declined','ended')),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(conversation_id) REFERENCES tc_chat_conversations(id) ON DELETE CASCADE,
 FOREIGN KEY(caller_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(callee_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tc_chat_calls_caller_status ON tc_chat_calls(caller_id,status,updated_at);
CREATE INDEX IF NOT EXISTS idx_tc_chat_calls_callee_status ON tc_chat_calls(callee_id,status,updated_at);
