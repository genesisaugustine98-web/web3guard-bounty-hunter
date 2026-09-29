CREATE TABLE IF NOT EXISTS scan_audit (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  chat_id TEXT,
  source TEXT NOT NULL,
  target TEXT NOT NULL,
  budget INTEGER NOT NULL,
  min_severity TEXT NOT NULL,
  discovery_only INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  error TEXT,
  run_url TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_audit_created_at ON scan_audit(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_audit_chat_id ON scan_audit(chat_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_audit_target ON scan_audit(target);
