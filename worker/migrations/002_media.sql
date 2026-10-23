-- EJECUTAR UNA SOLA VEZ en una base de datos que ya tenía la Fase 2 (añade la foto de perfil y los archivos).
ALTER TABLE nv_users ADD COLUMN avatar_id TEXT;

-- Fase 4 (fotos y videos): metadatos; el archivo vive en R2
CREATE TABLE IF NOT EXISTS nv_media (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('image','video')),
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  key TEXT NOT NULL,
  post_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nv_media_post ON nv_media(post_id);
CREATE INDEX IF NOT EXISTS nv_media_user ON nv_media(user_id);
