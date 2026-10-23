-- Nuvyru · Fase 2. Tablas con prefijo nv_ para convivir con otras tablas de la misma D1.
CREATE TABLE IF NOT EXISTS nv_users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  bio TEXT NOT NULL DEFAULT '',
  pass_hash TEXT NOT NULL,
  pass_salt TEXT NOT NULL,
  birth_year INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  avatar_id TEXT
);
CREATE TABLE IF NOT EXISTS nv_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nv_sessions_user ON nv_sessions(user_id);
CREATE TABLE IF NOT EXISTS nv_posts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  body TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','private')),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nv_posts_created ON nv_posts(created_at DESC);
CREATE INDEX IF NOT EXISTS nv_posts_user ON nv_posts(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS nv_likes (post_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (post_id, user_id));
CREATE TABLE IF NOT EXISTS nv_saves (post_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (post_id, user_id));
CREATE TABLE IF NOT EXISTS nv_rate (k TEXT PRIMARY KEY, count INTEGER NOT NULL, start INTEGER NOT NULL);

-- Fase 5 (mascotas): una mascota o huevo por usuario
CREATE TABLE IF NOT EXISTS nv_pets (
  user_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('egg','hatched')),
  species TEXT, name TEXT,
  requested_at INTEGER NOT NULL, hatch_at INTEGER NOT NULL, hatched_at INTEGER,
  energy INTEGER NOT NULL DEFAULT 70, joy INTEGER NOT NULL DEFAULT 70, xp INTEGER NOT NULL DEFAULT 0,
  xp_day TEXT NOT NULL DEFAULT '', xp_today INTEGER NOT NULL DEFAULT 0,
  accessory TEXT NOT NULL DEFAULT 'none',
  show_on_profile INTEGER NOT NULL DEFAULT 1, reminders INTEGER NOT NULL DEFAULT 0, rest_mode INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  last_feed INTEGER NOT NULL DEFAULT 0, last_play INTEGER NOT NULL DEFAULT 0,
  last_rest INTEGER NOT NULL DEFAULT 0, last_cuddle INTEGER NOT NULL DEFAULT 0
);

-- Medios (fotos y videos guardados en R2), perfiles ampliados y álbumes
CREATE TABLE IF NOT EXISTS nv_media (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('image','video')),
  mime TEXT NOT NULL, size INTEGER NOT NULL, key TEXT NOT NULL,
  attached INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS nv_media_user ON nv_media(user_id);
CREATE TABLE IF NOT EXISTS nv_post_media (
  post_id TEXT NOT NULL, media_id TEXT NOT NULL, pos INTEGER NOT NULL, PRIMARY KEY (post_id, media_id)
);
CREATE INDEX IF NOT EXISTS nv_post_media_post ON nv_post_media(post_id, pos);
CREATE TABLE IF NOT EXISTS nv_profiles (
  user_id TEXT PRIMARY KEY, avatar_id TEXT, banner_id TEXT,
  website TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '', pronouns TEXT NOT NULL DEFAULT '',
  accent TEXT NOT NULL DEFAULT 'violet'
);
