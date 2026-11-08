// Nuvyru API · cuentas, publicaciones, medios (R2), perfiles, búsqueda y mascotas
const enc = new TextEncoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rand = (n = 32) => b64(crypto.getRandomValues(new Uint8Array(n)));
const sha = async (s) => b64(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const pbkdf2 = async (pw, salt) =>
  b64(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 100000 },
    await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]), 256));
const same = (a, b) => a.length === b.length && [...a].reduce((x, c, i) => x | (c.charCodeAt(0) ^ b.charCodeAt(i)), 0) === 0;

const cors = (req, env) => {
  const list = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
  const o = req.headers.get("Origin");
  return {
    "Access-Control-Allow-Origin": list.includes(o) ? o : list[0] || "null",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    Vary: "Origin",
  };
};
const json = (req, env, body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...cors(req, env) } });
async function readBody(req) {
  if (Number(req.headers.get("Content-Length") || 0) > 10000) return null;
  try { return await req.json(); } catch { return null; }
}
async function limit(env, key, max, sec) {
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare("SELECT count, start FROM nv_rate WHERE k=?").bind(key).first();
  if (!row || now - row.start >= sec) {
    await env.DB.prepare("INSERT OR REPLACE INTO nv_rate (k,count,start) VALUES (?,?,?)").bind(key, 1, now).run();
    return true;
  }
  if (row.count >= max) return false;
  await env.DB.prepare("UPDATE nv_rate SET count=count+1 WHERE k=?").bind(key).run();
  return true;
}
const PROFILE = "SELECT u.id,u.username,u.display_name,u.bio,u.created_at,u.birth_year,pr.avatar_id,pr.banner_id,pr.website,pr.location,pr.pronouns,pr.accent FROM nv_users u LEFT JOIN nv_profiles pr ON pr.user_id=u.id";
async function auth(req, env) {
  const h = req.headers.get("Authorization") || "";
  if (!h.startsWith("Bearer ")) return null;
  return env.DB.prepare(PROFILE + " JOIN nv_sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?").bind(await sha(h.slice(7)), Date.now()).first();
}
async function newSession(env, uid) {
  const t = rand();
  await env.DB.prepare("INSERT INTO nv_sessions (token_hash,user_id,expires_at) VALUES (?,?,?)").bind(await sha(t), uid, Date.now() + 30 * 864e5).run();
  await env.DB.prepare("DELETE FROM nv_sessions WHERE expires_at<?").bind(Date.now()).run();
  return t;
}
const pub = (u) => ({
  username: u.username, display_name: u.display_name, bio: u.bio || "", avatar_id: u.avatar_id || null, banner_id: u.banner_id || null,
  website: u.website || "", location: u.location || "", pronouns: u.pronouns || "", accent: u.accent || "violet",
});

// ---- Medios (R2)
const UUID = /^[0-9a-f-]{36}$/;
const ACCENTS = ["violet", "blue", "cyan", "orange", "pink", "green"];
const MAX_IMG = 8 * 1024 * 1024, MAX_VID_SIMPLE = 95 * 1024 * 1024, MAX_VID = 200 * 1024 * 1024, PART = 20 * 1024 * 1024;
const IMG_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"], VID_TYPES = ["video/mp4", "video/webm", "video/quicktime"];
function sniff(mime, b) {
  if (!b || b.length < 12) return false;
  const at = (i, s) => [...s].every((c, k) => b[i + k] === c.charCodeAt(0));
  if (mime === "image/jpeg") return b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
  if (mime === "image/png") return b[0] === 0x89 && at(1, "PNG");
  if (mime === "image/gif") return at(0, "GIF8");
  if (mime === "image/webp") return at(0, "RIFF") && at(8, "WEBP");
  if (mime === "video/webm") return b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3;
  return at(4, "ftyp"); // mp4 / quicktime
}
async function dropMedia(env, rows) {
  if (!rows.length) return;
  if (env.MEDIA) for (let i = 0; i < rows.length; i += 1000) await env.MEDIA.delete(rows.slice(i, i + 1000).map((r) => r.key));
  for (let i = 0; i < rows.length; i += 50) {
    const part = rows.slice(i, i + 50);
    await env.DB.prepare(`DELETE FROM nv_media WHERE id IN (${part.map(() => "?").join(",")})`).bind(...part.map((r) => r.id)).run();
  }
}
const qs = (a) => a.map(() => "?").join(",");
// Copia el cuerpo de la petición a un destino de longitud fija, comprobando antes el tipo real del archivo
async function pipeBody(req, len, mime, put) {
  const reader = req.body.getReader(), first = await reader.read();
  if (mime && !sniff(mime, first.value)) return null;
  const { readable, writable } = new FixedLengthStream(len);
  const pipe = (async () => {
    const w = writable.getWriter(); await w.write(first.value);
    for (;;) { const r = await reader.read(); if (r.done) break; await w.write(r.value); }
    await w.close();
  })();
  const [res] = await Promise.all([put(readable), pipe]);
  return res;
}
async function dropUploads(env, rows) {
  for (const u of rows) { try { await env.MEDIA.resumeMultipartUpload(u.key, u.upload_id).abort(); } catch {} }
  for (const u of rows) await env.DB.prepare("DELETE FROM nv_uploads WHERE id=?").bind(u.id).run();
}

// ---- Publicaciones
// ---- Privacidad de cuenta y seguidores
const PRIVATE = (t) => `EXISTS (SELECT 1 FROM nv_privacy pv WHERE pv.user_id=${t} AND pv.private_account=1)`;
const FOLLOWS = (x, t) => `EXISTS (SELECT 1 FROM nv_follows f WHERE f.follower_id=${x} AND f.followee_id=${t} AND f.status='accepted')`;
const CANSEE = (x, t) => `(${t}=${x} OR NOT ${PRIVATE(t)} OR ${FOLLOWS(x, t)})`;
const ageOf = (by) => new Date().getFullYear() - Number(by || 0);
async function canSeeUser(env, me, uid) {
  if (uid === me.id) return true;
  const pv = await env.DB.prepare("SELECT private_account AS p FROM nv_privacy WHERE user_id=?").bind(uid).first();
  if (!pv || !pv.p) return true;
  return !!(await env.DB.prepare("SELECT 1 FROM nv_follows WHERE follower_id=? AND followee_id=? AND status='accepted'").bind(me.id, uid).first());
}
const POSTS_SQL = `SELECT p.id,p.body,p.visibility,p.created_at,u.username,u.display_name,pr.avatar_id,
 (SELECT COUNT(*) FROM nv_likes l WHERE l.post_id=p.id) AS like_count,
 (SELECT COUNT(*) FROM nv_comments cm WHERE cm.post_id=p.id) AS comment_count,
 EXISTS(SELECT 1 FROM nv_likes l WHERE l.post_id=p.id AND l.user_id=?1) AS liked,
 EXISTS(SELECT 1 FROM nv_saves s WHERE s.post_id=p.id AND s.user_id=?1) AS saved
 FROM nv_posts p JOIN nv_users u ON u.id=p.user_id LEFT JOIN nv_profiles pr ON pr.user_id=u.id
 WHERE (p.user_id=?1 OR (p.visibility='public' AND ${CANSEE("?1", "p.user_id")})) AND (?2 IS NULL OR u.username=?2) AND (?3 IS NULL OR p.created_at<?3)
 AND (?4 IS NULL OR EXISTS(SELECT 1 FROM nv_post_media pm JOIN nv_media m ON m.id=pm.media_id WHERE pm.post_id=p.id AND (?4='media' OR m.kind=?4)))
 AND (?5 IS NULL OR p.body LIKE ?5 ESCAPE '\\') AND (?6=0 OR (p.visibility='public' AND NOT ${PRIVATE("p.user_id")})) AND (?7 IS NULL OR p.id=?7) AND NOT EXISTS (SELECT 1 FROM nv_blocks bk WHERE (bk.blocker=?1 AND bk.blocked=p.user_id) OR (bk.blocker=p.user_id AND bk.blocked=?1))
 AND (?8=0 OR p.user_id=?1 OR ${FOLLOWS("?1", "p.user_id")})
 ORDER BY p.created_at DESC LIMIT 30`;
async function listPosts(env, me, o = {}) {
  const { results } = await env.DB.prepare(POSTS_SQL).bind(me.id, o.user ?? null, o.before ?? null, o.kind ?? null, o.q ?? null, o.pub ? 1 : 0, o.id ?? null, o.following ? 1 : 0).all();
  const ids = results.map((r) => r.id), by = {};
  if (ids.length) {
    const { results: ms } = await env.DB.prepare(`SELECT pm.post_id,m.id,m.kind FROM nv_post_media pm JOIN nv_media m ON m.id=pm.media_id WHERE pm.post_id IN (${qs(ids)}) ORDER BY pm.pos`).bind(...ids).all();
    for (const x of ms) (by[x.post_id] ||= []).push({ id: x.id, kind: x.kind });
  }
  return results.map((r) => ({ ...r, avatar_id: r.avatar_id || null, liked: !!r.liked, saved: !!r.saved, mine: r.username === me.username, media: by[r.id] || [] }));
}

// ---- Mascotas
const HATCH_MS = 4 * 3600e3, FLOOR = 30, DAILY_XP = 60, DECAY_PER_H = 1;
const SPECIES = ["nubi", "lumo", "brisa", "zafi"], DEF = { nubi: "Nubi", lumo: "Lumo", brisa: "Brisa", zafi: "Zafi" };
const CARE = {
  feed: { cd: 1800, energy: 20, joy: 5, xp: 5, col: "last_feed" },
  play: { cd: 1200, energy: -8, joy: 15, xp: 8, col: "last_play", minEnergy: 10 },
  rest: { cd: 3600, energy: 30, joy: 0, xp: 2, col: "last_rest" },
  cuddle: { cd: 600, energy: 0, joy: 8, xp: 2, col: "last_cuddle" },
};
const STAGES = ["cria", "joven", "adulto"], UNLOCK = { hat: "cria", glasses: "joven", scarf: "adulto" };
const stageOf = (xp) => (xp >= 300 ? "adulto" : xp >= 100 ? "joven" : "cria");
const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)));
const day = (t) => new Date(t).toISOString().slice(0, 10);
const decay = (v, hrs) => (v <= FLOOR ? v : Math.max(FLOOR, v - hrs * DECAY_PER_H));
function petView(r, now) {
  if (r.status === "egg") return { status: "egg", hatch_at: r.hatch_at, hatch_in_ms: Math.max(0, r.hatch_at - now) };
  const hrs = r.rest_mode ? 0 : Math.max(0, (now - r.updated_at) / 36e5), st = stageOf(r.xp), cooldowns = {};
  for (const [k, c] of Object.entries(CARE)) cooldowns[k] = Math.max(0, Math.ceil((r[c.col] + c.cd * 1000 - now) / 1000));
  return {
    status: "hatched", species: r.species, name: r.name, stage: st, xp: r.xp, next_xp: st === "cria" ? 100 : st === "joven" ? 300 : null,
    energy: Math.round(decay(r.energy, hrs)), joy: Math.round(decay(r.joy, hrs)), accessory: r.accessory,
    show_on_profile: !!r.show_on_profile, reminders: !!r.reminders, rest_mode: !!r.rest_mode,
    cooldowns, xp_today: r.xp_day === day(now) ? r.xp_today : 0, daily_xp_cap: DAILY_XP,
  };
}
async function getPet(env, uid, now) {
  const q = () => env.DB.prepare("SELECT * FROM nv_pets WHERE user_id=?").bind(uid).first();
  let r = await q();
  if (r && r.status === "egg" && now >= r.hatch_at) {
    const sp = SPECIES[crypto.getRandomValues(new Uint32Array(1))[0] % SPECIES.length];
    await env.DB.prepare("UPDATE nv_pets SET status='hatched',species=?,name=?,hatched_at=?,energy=70,joy=70,updated_at=? WHERE user_id=?").bind(sp, DEF[sp], now, now, uid).run();
    r = await q();
  }
  return r;
}

const SETTING_FLAGS = ["orya_posts", "notif_likes", "notif_comments", "notif_follows"];
async function getSettings(env, uid) {
  const r = (await env.DB.prepare("SELECT * FROM nv_settings WHERE user_id=?").bind(uid).first()) || { default_visibility: "public", orya_posts: 0, notif_likes: 1, notif_comments: 1, notif_follows: 1 };
  const pv = (await env.DB.prepare("SELECT private_account,msg_who FROM nv_privacy WHERE user_id=?").bind(uid).first()) || { private_account: 0, msg_who: "everyone" };
  return { default_visibility: r.default_visibility, ...Object.fromEntries(SETTING_FLAGS.map((k) => [k, !!r[k]])), private_account: !!pv.private_account, msg_who: pv.msg_who };
}
// motivos de denuncia; 1 = prioridad alta (seguridad de personas)
const REASONS = { spam: 0, harassment: 0, hate: 0, sexual: 0, violence: 1, selfharm: 1, minor: 1, scam: 0, illegal: 0, ip: 0, bug: 0, other: 0 };
// ---- Historias
const EMOJIS = ["❤️", "😂", "😮", "😢", "🔥", "👏"];
const NOBLOCK = (x, t) => `NOT EXISTS (SELECT 1 FROM nv_blocks bk WHERE (bk.blocker=${x} AND bk.blocked=${t}) OR (bk.blocker=${t} AND bk.blocked=${x}))`;
const STORY_SQL = `SELECT s.id,s.user_id,s.text,s.bg,s.visibility,s.created_at,s.expires_at,s.media_id,m.kind AS media_kind,u.username,u.display_name,pr.avatar_id,
 EXISTS(SELECT 1 FROM nv_story_views v WHERE v.story_id=s.id AND v.viewer_id=?1) AS seen,
 (SELECT r.emoji FROM nv_story_reactions r WHERE r.story_id=s.id AND r.user_id=?1) AS my_reaction
 FROM nv_stories s JOIN nv_users u ON u.id=s.user_id LEFT JOIN nv_profiles pr ON pr.user_id=u.id LEFT JOIN nv_media m ON m.id=s.media_id`;
const shapeStory = (r) => ({
  id: r.id, text: r.text, bg: r.bg, visibility: r.visibility, created_at: r.created_at, expires_at: r.expires_at,
  media: r.media_id ? { id: r.media_id, kind: r.media_kind } : null, seen: !!r.seen, my_reaction: r.my_reaction || null,
  username: r.username, display_name: r.display_name, avatar_id: r.avatar_id || null,
});
function groupStories(rows, me) {
  const by = new Map();
  for (const r of rows) {
    if (!by.has(r.user_id)) by.set(r.user_id, { username: r.username, display_name: r.display_name, avatar_id: r.avatar_id || null, is_me: r.user_id === me.id, stories: [] });
    by.get(r.user_id).stories.push(shapeStory(r));
  }
  const g = [...by.values()].map((x) => ({ ...x, all_seen: x.is_me || x.stories.every((st) => st.seen), latest: x.stories[x.stories.length - 1].created_at }));
  return g.sort((a, b) => (b.is_me - a.is_me) || (a.all_seen - b.all_seen) || (b.latest - a.latest));
}
const POST_OK = `SELECT p.id,p.user_id FROM nv_posts p WHERE p.id=?2 AND (p.user_id=?1 OR (p.visibility='public' AND ${CANSEE("?1", "p.user_id")})) AND ${NOBLOCK("?1", "p.user_id")}`;
const visiblePost = (env, me, id) => env.DB.prepare(POST_OK).bind(me.id, id).first();
const commentCtx = async (env, me, id) => {
  const c = UUID.test(id) && (await env.DB.prepare("SELECT c.id,c.post_id,c.user_id,c.parent_id,po.user_id AS post_owner FROM nv_comments c JOIN nv_posts po ON po.id=c.post_id WHERE c.id=?").bind(id).first());
  return c && (await visiblePost(env, me, c.post_id)) ? c : null;
};
const visibleStory = (env, me, id, now) =>
  env.DB.prepare(STORY_SQL + ` WHERE s.id=?2 AND s.expires_at>?3 AND (s.user_id=?1 OR (s.visibility='public' AND ${CANSEE("?1", "s.user_id")})) AND ${NOBLOCK("?1", "s.user_id")}`).bind(me.id, id, now).first();
async function purgeStories(env, rows) {
  for (const r of rows) {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM nv_story_views WHERE story_id=?").bind(r.id), env.DB.prepare("DELETE FROM nv_story_reactions WHERE story_id=?").bind(r.id),
      env.DB.prepare("DELETE FROM nv_story_replies WHERE story_id=?").bind(r.id), env.DB.prepare("DELETE FROM nv_highlight_items WHERE story_id=?").bind(r.id),
      env.DB.prepare("DELETE FROM nv_stories WHERE id=?").bind(r.id),
    ]);
  }
  await dropMedia(env, rows.filter((r) => r.media_id).map((r) => ({ id: r.media_id, key: r.key })));
}
// ---- Mensajes y rachas
const dayOf = (t) => new Date(t).toISOString().slice(0, 10);
const dayDiff = (a, b) => Math.round((Date.parse(b) - Date.parse(a)) / 864e5);
const pairKey = (x, y) => (x < y ? [x, y] : [y, x]);
const STREAK_BADGES = [[7, "bronce", "Racha de 7 días"], [30, "plata", "Racha de 30 días"], [100, "oro", "Racha de 100 días"], [200, "platino", "Racha de 200 días"], [365, "diamante", "Racha de 365 días"]];
async function canMessage(env, me, t) {
  if (t.id === me.id) return [400, "self", "No puedes escribirte a ti mismo"];
  if (await env.DB.prepare("SELECT 1 FROM nv_blocks WHERE (blocker=? AND blocked=?) OR (blocker=? AND blocked=?)").bind(me.id, t.id, t.id, me.id).first()) return [404, "not_found", "Ese usuario no existe"];
  const pv = await env.DB.prepare("SELECT msg_who FROM nv_privacy WHERE user_id=?").bind(t.id).first(), minor = ageOf(t.birth_year) < 18;
  let who = pv ? pv.msg_who : "everyone";
  if (minor && who === "everyone") who = "following";
  if (who === "nobody") return [403, "no_messages", "Esta persona no recibe mensajes"];
  if (who === "following" && !(await env.DB.prepare("SELECT 1 FROM nv_follows WHERE follower_id=? AND followee_id=? AND status='accepted'").bind(t.id, me.id).first()))
    return [403, "not_allowed", minor ? "Por seguridad, esta persona solo recibe mensajes de quienes ella sigue" : "Esta persona solo recibe mensajes de quienes ella sigue"];
  return null;
}
async function awardStreakBadges(env, ids, count, now) {
  for (const [n, tier] of STREAK_BADGES) if (count >= n) for (const id of ids) await env.DB.prepare("INSERT OR IGNORE INTO nv_badges (user_id,code,tier,earned_at) VALUES (?,?,?,?)").bind(id, "streak_" + n, tier, now).run();
}
// Una racha cuenta un día cuando las dos personas se escriben ese día. Se permiten hasta 2 días de descanso sin perderla.
async function touchStreak(env, meId, otherId, now) {
  const [a, b] = pairKey(meId, otherId);
  const s = await env.DB.prepare("SELECT * FROM nv_streaks WHERE user_a=? AND user_b=? AND status='active'").bind(a, b).first();
  if (!s) return null;
  const day = dayOf(now), aLast = meId === a ? day : s.a_last, bLast = meId === b ? day : s.b_last;
  let { count, best, total_days: total, last_day: last } = s;
  const done = aLast === day && bLast === day;
  if (done && last !== day) {
    const gap = last ? (s.paused ? 1 : dayDiff(last, day)) : 1;
    count = last && gap <= 3 ? count + 1 : 1; total += 1; best = Math.max(best, count); last = day;
  }
  await env.DB.prepare("UPDATE nv_streaks SET a_last=?, b_last=?, count=?, best=?, total_days=?, last_day=? WHERE id=?").bind(aLast, bLast, count, best, total, last, s.id).run();
  if (count > s.count) await awardStreakBadges(env, [a, b], count, now);
  return { count, best, total_days: total, done_today: done };
}
const PLANNED = { "/api/notifications": 3, "/api/orya": 6, "/api/live": 7 };

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: cors(req, env) });
    const url = new URL(req.url), p = url.pathname, m = req.method;
    const out = (b, s = 200) => json(req, env, b, s);
    const fail = (s, error, message) => out({ error, message }, s);
    try {
      if (p === "/api/health") return out({ ok: true, service: "nuvyru-api", db: !!env.DB, storage: !!env.MEDIA });
      const hit = Object.keys(PLANNED).find((k) => p.startsWith(k));
      if (hit) return fail(501, "not_implemented", "Esta función llega en la fase " + PLANNED[hit]);
      if (!env.DB) return fail(503, "no_db", "La base de datos D1 no está configurada");
      const ip = req.headers.get("CF-Connecting-IP") || "local";
      let mt;

      // Ver un archivo (las etiquetas <img> y <video> no envían sesión; el id es imposible de adivinar)
      if ((mt = p.match(/^\/api\/media\/([0-9a-f-]{36})$/)) && m === "GET") {
        if (!env.MEDIA) return fail(503, "no_storage", "El almacenamiento no está configurado");
        const row = await env.DB.prepare("SELECT key,mime FROM nv_media WHERE id=?").bind(mt[1]).first();
        const o = row && (await env.MEDIA.get(row.key, { range: req.headers }));
        if (!o) return fail(404, "not_found", "Archivo no encontrado");
        const h = new Headers({ ...cors(req, env), "Content-Type": row.mime, "Accept-Ranges": "bytes", "Cache-Control": "public, max-age=31536000, immutable", "Cross-Origin-Resource-Policy": "cross-origin", "X-Content-Type-Options": "nosniff" });
        let status = 200;
        if (req.headers.get("Range") && o.range) {
          const off = o.range.offset ?? Math.max(0, o.size - o.range.suffix), len = o.range.length ?? o.size - off;
          h.set("Content-Range", `bytes ${off}-${off + len - 1}/${o.size}`); h.set("Content-Length", String(len)); status = 206;
        } else h.set("Content-Length", String(o.size));
        return new Response(o.body, { status, headers: h });
      }

      if (p === "/api/auth/register" && m === "POST") {
        if (!(await limit(env, "reg:" + ip, 5, 3600))) return fail(429, "rate_limited", "Demasiados intentos. Inténtalo más tarde");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const username = String(b.username || "").trim().toLowerCase(), name = String(b.display_name || "").trim();
        const pw = String(b.password || ""), by = Number(b.birth_year), yr = new Date().getFullYear();
        if (!/^[a-z0-9_.]{3,24}$/.test(username)) return fail(400, "invalid_username", "El usuario debe tener de 3 a 24 caracteres: letras, números, punto o guion bajo");
        if (name.length < 1 || name.length > 40) return fail(400, "invalid_name", "Escribe tu nombre (máximo 40 caracteres)");
        if (pw.length < 8 || pw.length > 128) return fail(400, "invalid_password", "La contraseña debe tener entre 8 y 128 caracteres");
        if (!Number.isInteger(by) || by < 1900 || by > yr) return fail(400, "invalid_birth", "Escribe un año de nacimiento válido");
        if (yr - by < 13) return fail(403, "underage", "Debes tener al menos 13 años para crear una cuenta");
        if (await env.DB.prepare("SELECT 1 FROM nv_users WHERE username=?").bind(username).first()) return fail(409, "username_taken", "Ese nombre de usuario ya existe");
        const id = crypto.randomUUID(), salt = rand(16), hash = await pbkdf2(pw, salt);
        try {
          await env.DB.prepare("INSERT INTO nv_users (id,username,display_name,bio,pass_hash,pass_salt,birth_year,created_at) VALUES (?,?,?,?,?,?,?,?)")
            .bind(id, username, name, "", hash, salt, by, Date.now()).run();
        } catch { return fail(409, "username_taken", "Ese nombre de usuario ya existe"); }
        if (yr - by < 18) await env.DB.prepare("INSERT INTO nv_privacy (user_id,private_account,msg_who) VALUES (?,?,?)").bind(id, yr - by < 16 ? 1 : 0, "following").run();
        return out({ token: await newSession(env, id), user: pub({ username, display_name: name }) }, 201);
      }
      if (p === "/api/auth/login" && m === "POST") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const username = String(b.username || "").trim().toLowerCase(), pw = String(b.password || "").slice(0, 128);
        if (!(await limit(env, "login:" + ip + ":" + username, 10, 900))) return fail(429, "rate_limited", "Demasiados intentos. Espera unos minutos");
        const row = await env.DB.prepare(PROFILE.replace("u.bio,", "u.bio,u.pass_hash,u.pass_salt,") + " WHERE u.username=?").bind(username).first();
        const h = await pbkdf2(pw, row ? row.pass_salt : "x".repeat(22));
        if (!row || !same(h, row.pass_hash)) return fail(401, "invalid_credentials", "Usuario o contraseña incorrectos");
        return out({ token: await newSession(env, row.id), user: pub(row) });
      }

      const me = await auth(req, env);
      if (!me) return fail(401, "unauthorized", "Inicia sesión para continuar");

      if (p === "/api/auth/logout" && m === "POST") {
        await env.DB.prepare("DELETE FROM nv_sessions WHERE token_hash=?").bind(await sha(req.headers.get("Authorization").slice(7))).run();
        return out({ ok: true });
      }
      if (p === "/api/me" && m === "GET") return out({ user: pub(me) });
      if (p === "/api/me" && m === "PATCH") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const pick = (k, cur) => (b[k] === undefined ? cur || "" : String(b[k]).trim());
        const name = pick("display_name", me.display_name), bio = pick("bio", me.bio), loc = pick("location", me.location), pron = pick("pronouns", me.pronouns), site = pick("website", me.website);
        const accent = b.accent === undefined ? me.accent || "violet" : String(b.accent);
        if (name.length < 1 || name.length > 40) return fail(400, "invalid_name", "El nombre debe tener entre 1 y 40 caracteres");
        if (bio.length > 200) return fail(400, "invalid_bio", "La biografía admite hasta 200 caracteres");
        if (loc.length > 40) return fail(400, "invalid_location", "La ubicación admite hasta 40 caracteres");
        if (pron.length > 20) return fail(400, "invalid_pronouns", "Los pronombres admiten hasta 20 caracteres");
        if (!ACCENTS.includes(accent)) return fail(400, "invalid_accent", "Color no válido");
        if (site) {
          let ok = site.length <= 100;
          try { ok = ok && ["http:", "https:"].includes(new URL(site).protocol); } catch { ok = false; }
          if (!ok) return fail(400, "invalid_website", "Escribe una dirección web válida que empiece por https://");
        }
        let avatar = me.avatar_id || null, banner = me.banner_id || null;
        const oldIds = [];
        for (const k of ["avatar_id", "banner_id"]) {
          if (b[k] === undefined) continue;
          const v = b[k] ? String(b[k]) : null, cur = k === "avatar_id" ? avatar : banner;
          if (v && v !== cur && (!UUID.test(v) || !(await env.DB.prepare("SELECT 1 FROM nv_media WHERE id=? AND user_id=? AND kind='image' AND NOT EXISTS (SELECT 1 FROM nv_post_media pm WHERE pm.media_id=nv_media.id)").bind(v, me.id).first()))) return fail(400, "invalid_media", "La imagen no es válida (sube una foto nueva para tu perfil)");
          if (v !== cur) { if (cur) oldIds.push(cur); if (k === "avatar_id") avatar = v; else banner = v; }
        }
        const keep = [avatar, banner].filter(Boolean);
        await env.DB.batch([
          env.DB.prepare("UPDATE nv_users SET display_name=?, bio=? WHERE id=?").bind(name, bio, me.id),
          env.DB.prepare("INSERT INTO nv_profiles (user_id,avatar_id,banner_id,website,location,pronouns,accent) VALUES (?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET avatar_id=excluded.avatar_id,banner_id=excluded.banner_id,website=excluded.website,location=excluded.location,pronouns=excluded.pronouns,accent=excluded.accent")
            .bind(me.id, avatar, banner, site, loc, pron, accent),
          ...(keep.length ? [env.DB.prepare(`UPDATE nv_media SET attached=1 WHERE id IN (${qs(keep)})`).bind(...keep)] : []),
        ]);
        const gone = oldIds.filter((x) => x !== avatar && x !== banner);
        if (gone.length) { const { results } = await env.DB.prepare(`SELECT id,key FROM nv_media WHERE id IN (${qs(gone)}) AND user_id=? AND NOT EXISTS (SELECT 1 FROM nv_post_media pm WHERE pm.media_id=nv_media.id)`).bind(...gone, me.id).all(); await dropMedia(env, results); }
        return out({ user: pub({ ...me, display_name: name, bio, avatar_id: avatar, banner_id: banner, website: site, location: loc, pronouns: pron, accent }) });
      }
      if (p === "/api/me" && m === "DELETE") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const row = await env.DB.prepare("SELECT pass_hash,pass_salt FROM nv_users WHERE id=?").bind(me.id).first();
        if (!same(await pbkdf2(String(b.password || "").slice(0, 128), row.pass_salt), row.pass_hash)) return fail(403, "invalid_credentials", "Contraseña incorrecta");
        const { results: mine } = await env.DB.prepare("SELECT id,key FROM nv_media WHERE user_id=?").bind(me.id).all();
        if (env.MEDIA) for (let i = 0; i < mine.length; i += 1000) await env.MEDIA.delete(mine.slice(i, i + 1000).map((r) => r.key));
        if (env.MEDIA) { const { results: ups } = await env.DB.prepare("SELECT id,key,upload_id FROM nv_uploads WHERE user_id=?").bind(me.id).all(); await dropUploads(env, ups); }
        const own = "(SELECT id FROM nv_posts WHERE user_id=?)";
        await env.DB.batch([
          env.DB.prepare(`DELETE FROM nv_likes WHERE post_id IN ${own} OR user_id=?`).bind(me.id, me.id),
          env.DB.prepare(`DELETE FROM nv_saves WHERE post_id IN ${own} OR user_id=?`).bind(me.id, me.id),
          env.DB.prepare(`DELETE FROM nv_post_media WHERE post_id IN ${own}`).bind(me.id),
          env.DB.prepare("DELETE FROM nv_follows WHERE follower_id=? OR followee_id=?").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_streaks WHERE user_a=? OR user_b=?").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_badges WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_messages WHERE sender_id=? OR conv_id IN (SELECT c.id FROM nv_convs c JOIN nv_conv_members m ON m.conv_id=c.id WHERE c.kind='direct' AND m.user_id=?)").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_conv_members WHERE conv_id IN (SELECT c.id FROM nv_convs c JOIN nv_conv_members m ON m.conv_id=c.id WHERE c.kind='direct' AND m.user_id=?)").bind(me.id),
          env.DB.prepare("DELETE FROM nv_conv_members WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_convs WHERE id NOT IN (SELECT conv_id FROM nv_conv_members)"),
          env.DB.prepare("DELETE FROM nv_privacy WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_comment_likes WHERE user_id=? OR comment_id IN (SELECT id FROM nv_comments WHERE user_id=? OR post_id IN (SELECT id FROM nv_posts WHERE user_id=?) OR parent_id IN (SELECT id FROM nv_comments WHERE user_id=?))").bind(me.id, me.id, me.id, me.id),
          env.DB.prepare("DELETE FROM nv_comment_reports WHERE reporter_id=? OR comment_id IN (SELECT id FROM nv_comments WHERE user_id=? OR post_id IN (SELECT id FROM nv_posts WHERE user_id=?) OR parent_id IN (SELECT id FROM nv_comments WHERE user_id=?))").bind(me.id, me.id, me.id, me.id),
          env.DB.prepare("DELETE FROM nv_comments WHERE user_id=? OR post_id IN (SELECT id FROM nv_posts WHERE user_id=?) OR parent_id IN (SELECT id FROM nv_comments WHERE user_id=?)").bind(me.id, me.id, me.id),
          env.DB.prepare("DELETE FROM nv_highlight_items WHERE highlight_id IN (SELECT id FROM nv_highlights WHERE user_id=?) OR story_id IN (SELECT id FROM nv_stories WHERE user_id=?)").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_highlights WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_story_views WHERE viewer_id=? OR story_id IN (SELECT id FROM nv_stories WHERE user_id=?)").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_story_reactions WHERE user_id=? OR story_id IN (SELECT id FROM nv_stories WHERE user_id=?)").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_story_replies WHERE from_id=? OR story_id IN (SELECT id FROM nv_stories WHERE user_id=?)").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_stories WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_reports WHERE reporter_id=? OR (target_type='user' AND target_id=?) OR (target_type='post' AND target_id IN (SELECT id FROM nv_posts WHERE user_id=?))").bind(me.id, me.id, me.id),
          env.DB.prepare("DELETE FROM nv_blocks WHERE blocker=? OR blocked=?").bind(me.id, me.id),
          env.DB.prepare("DELETE FROM nv_settings WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_media WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_posts WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_profiles WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_pets WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_sessions WHERE user_id=?").bind(me.id),
          env.DB.prepare("DELETE FROM nv_users WHERE id=?").bind(me.id),
        ]);
        return out({ ok: true });
      }

      // ---- Videos grandes (hasta 200 MB): subida por partes de 20 MB
      if (p === "/api/media/multipart" && m === "POST") {
        if (!env.MEDIA) return fail(503, "no_storage", "El almacenamiento de archivos (R2) no está configurado");
        if (!(await limit(env, "mpc:" + me.id, 10, 3600))) return fail(429, "rate_limited", "Has iniciado demasiadas subidas. Inténtalo en un rato");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const mime = String(b.mime || "").toLowerCase(), size = Number(b.size);
        if (!VID_TYPES.includes(mime)) return fail(415, "unsupported_type", "Formato no admitido. Videos: MP4, WEBM o MOV");
        if (!Number.isInteger(size) || size <= 0) return fail(400, "bad_request", "Tamaño no válido");
        if (size > MAX_VID) return fail(413, "too_large", "El video supera 200 MB");
        const { results: old } = await env.DB.prepare("SELECT id,key,upload_id FROM nv_uploads WHERE created_at<? LIMIT 10").bind(Date.now() - 864e5).all();
        await dropUploads(env, old);
        const id = crypto.randomUUID(), key = `u/${me.id}/${id}`;
        const mp = await env.MEDIA.createMultipartUpload(key, { httpMetadata: { contentType: mime } });
        await env.DB.prepare("INSERT INTO nv_uploads (id,user_id,upload_id,key,mime,size,created_at) VALUES (?,?,?,?,?,?,?)").bind(id, me.id, mp.uploadId, key, mime, size, Date.now()).run();
        return out({ upload: { id, part_size: PART, parts: Math.ceil(size / PART) } }, 201);
      }
      if ((mt = p.match(/^\/api\/media\/multipart\/([0-9a-f-]{36})\/(\d+|complete|abort)$/)) && ["PUT", "POST"].includes(m)) {
        const up = await env.DB.prepare("SELECT * FROM nv_uploads WHERE id=? AND user_id=?").bind(mt[1], me.id).first();
        if (!up) return fail(404, "not_found", "Subida no encontrada");
        const total = Math.ceil(up.size / PART), mp = env.MEDIA.resumeMultipartUpload(up.key, up.upload_id);
        if (mt[2] === "abort" && m === "POST") { await dropUploads(env, [up]); return out({ ok: true }); }
        if (mt[2] === "complete" && m === "POST") {
          const b = await readBody(req), parts = b && Array.isArray(b.parts) ? b.parts : [];
          const nums = parts.map((x) => Number(x.partNumber));
          if (parts.length !== total || new Set(nums).size !== total || nums.some((n) => !Number.isInteger(n) || n < 1 || n > total) || parts.some((x) => typeof x.etag !== "string")) return fail(400, "bad_parts", "Faltan partes del video");
          let obj;
          try { obj = await mp.complete(parts.map((x) => ({ partNumber: Number(x.partNumber), etag: x.etag })).sort((a, c) => a.partNumber - c.partNumber)); }
          catch { await dropUploads(env, [up]); return fail(400, "complete_failed", "No se pudo completar la subida. Inténtalo de nuevo"); }
          if (obj.size !== up.size) { await env.MEDIA.delete(up.key); await dropUploads(env, [up]); return fail(400, "size_mismatch", "El tamaño del video no coincide"); }
          await env.DB.batch([
            env.DB.prepare("INSERT INTO nv_media (id,user_id,kind,mime,size,key,created_at) VALUES (?,?,'video',?,?,?,?)").bind(up.id, me.id, up.mime, up.size, up.key, Date.now()),
            env.DB.prepare("DELETE FROM nv_uploads WHERE id=?").bind(up.id),
          ]);
          return out({ media: { id: up.id, kind: "video", mime: up.mime, size: up.size } }, 201);
        }
        if (/^\d+$/.test(mt[2]) && m === "PUT") {
          const n = Number(mt[2]), len = Number(req.headers.get("Content-Length") || 0);
          if (n < 1 || n > total) return fail(400, "bad_part", "Número de parte no válido");
          if (!req.body || len !== (n < total ? PART : up.size - PART * (total - 1))) return fail(400, "bad_part_size", "Tamaño de parte incorrecto");
          let part;
          try { part = await pipeBody(req, len, n === 1 ? up.mime : null, (rs) => mp.uploadPart(n, rs)); }
          catch { return fail(400, "upload_failed", "La parte se interrumpió. Reinténtala"); }
          if (!part) return fail(415, "invalid_file", "El archivo no es un video válido");
          return out({ partNumber: part.partNumber, etag: part.etag });
        }
        return fail(405, "method_not_allowed", "Método no permitido");
      }

      // ---- Subir fotos y videos (cuerpo binario directo; se guarda en R2 sin cargarlo entero en memoria)
      if (p === "/api/media" && m === "POST") {
        if (!env.MEDIA) return fail(503, "no_storage", "El almacenamiento de archivos (R2) no está configurado");
        if (!(await limit(env, "up:" + me.id, 40, 3600))) return fail(429, "rate_limited", "Has subido demasiados archivos. Inténtalo en un rato");
        const kind = url.searchParams.get("kind"), mime = (req.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase();
        if (!["image", "video"].includes(kind) || !(kind === "image" ? IMG_TYPES : VID_TYPES).includes(mime)) return fail(415, "unsupported_type", "Formato no admitido. Fotos: JPG, PNG, WEBP o GIF. Videos: MP4, WEBM o MOV");
        const len = Number(req.headers.get("Content-Length") || 0);
        if (!len || !req.body) return fail(411, "length_required", "Falta el tamaño del archivo");
        if (len > (kind === "image" ? MAX_IMG : MAX_VID_SIMPLE)) return fail(413, "too_large", kind === "image" ? "La foto supera 8 MB" : "Este video es demasiado grande para subirlo de una vez (usa la subida por partes)");
        const reader = req.body.getReader(), first = await reader.read();
        if (!sniff(mime, first.value)) return fail(415, "invalid_file", "El archivo no es válido o no coincide con su formato");
        const id = crypto.randomUUID(), key = `u/${me.id}/${id}`, { readable, writable } = new FixedLengthStream(len);
        const pipe = (async () => {
          const w = writable.getWriter(); await w.write(first.value);
          for (;;) { const r = await reader.read(); if (r.done) break; await w.write(r.value); }
          await w.close();
        })();
        try { await Promise.all([env.MEDIA.put(key, readable, { httpMetadata: { contentType: mime } }), pipe]); }
        catch { await env.MEDIA.delete(key).catch(() => {}); return fail(400, "upload_failed", "La subida se interrumpió. Inténtalo de nuevo"); }
        await env.DB.prepare("INSERT INTO nv_media (id,user_id,kind,mime,size,key,created_at) VALUES (?,?,?,?,?,?,?)").bind(id, me.id, kind, mime, len, key, Date.now()).run();
        const { results: orphans } = await env.DB.prepare("SELECT id,key FROM nv_media WHERE attached=0 AND created_at<? LIMIT 20").bind(Date.now() - 864e5).all();
        await dropMedia(env, orphans);
        return out({ media: { id, kind, mime, size: len } }, 201);
      }

      // ---- Mascotas
      if (p === "/api/pet" && m === "GET") {
        const now = Date.now(), r = await getPet(env, me.id, now);
        return out({ pet: r ? petView(r, now) : null });
      }
      if (p === "/api/pet/request" && m === "POST") {
        if (!(await limit(env, "petreq:" + me.id, 3, 86400))) return fail(429, "rate_limited", "Has pedido demasiadas mascotas hoy");
        if (await env.DB.prepare("SELECT 1 FROM nv_pets WHERE user_id=?").bind(me.id).first()) return fail(409, "already_has_pet", "Ya tienes una mascota o un huevo");
        const now = Date.now();
        await env.DB.prepare("INSERT INTO nv_pets (user_id,status,requested_at,hatch_at,updated_at) VALUES (?,'egg',?,?,?)").bind(me.id, now, now + HATCH_MS, now).run();
        return out({ pet: petView(await getPet(env, me.id, now), now) }, 201);
      }
      if (p === "/api/pet/care" && m === "POST") {
        const b = await readBody(req), c = b && Object.hasOwn(CARE, b.action) ? CARE[b.action] : null;
        if (!c) return fail(400, "invalid_action", "Acción no válida");
        if (!(await limit(env, "care:" + me.id, 60, 3600))) return fail(429, "rate_limited", "Demasiadas acciones seguidas");
        const now = Date.now(), r = await getPet(env, me.id, now);
        if (!r || r.status !== "hatched") return fail(409, "not_hatched", "Tu mascota aún no ha eclosionado");
        if (r.rest_mode) return fail(409, "rest_mode", "El modo descanso está activado");
        const left = Math.ceil((r[c.col] + c.cd * 1000 - now) / 1000);
        if (left > 0) return out({ error: "cooldown", message: "Todavía no es momento. Vuelve en " + Math.ceil(left / 60) + " min", retry_in: left }, 429);
        const hrs = Math.max(0, (now - r.updated_at) / 36e5);
        let e = decay(r.energy, hrs), j = decay(r.joy, hrs);
        if (c.minEnergy && e < c.minEnergy) return fail(409, "tired", "Está muy cansado para jugar. Déjalo descansar");
        e = clamp(e + c.energy); j = clamp(j + c.joy);
        const used = r.xp_day === day(now) ? r.xp_today : 0, gain = Math.max(0, Math.min(c.xp, DAILY_XP - used));
        await env.DB.prepare(`UPDATE nv_pets SET energy=?,joy=?,xp=xp+?,xp_day=?,xp_today=?,updated_at=?,${c.col}=? WHERE user_id=?`).bind(e, j, gain, day(now), used + gain, now, now, me.id).run();
        return out({ pet: petView(await getPet(env, me.id, now), now), gained: gain });
      }
      if (p === "/api/pet" && m === "PATCH") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const now = Date.now(), r = await getPet(env, me.id, now);
        if (!r || r.status !== "hatched") return fail(409, "not_hatched", "Tu mascota aún no ha eclosionado");
        let name = r.name, acc = r.accessory;
        if (b.name !== undefined) {
          name = String(b.name).trim();
          if (!/^[\p{L}\p{N} ._'-]{1,20}$/u.test(name)) return fail(400, "invalid_name", "El nombre debe tener de 1 a 20 caracteres (letras, números o espacios)");
        }
        if (b.accessory !== undefined) {
          acc = String(b.accessory);
          if (acc !== "none" && !Object.hasOwn(UNLOCK, acc)) return fail(400, "invalid_accessory", "Accesorio no válido");
          if (acc !== "none" && STAGES.indexOf(stageOf(r.xp)) < STAGES.indexOf(UNLOCK[acc])) return fail(403, "locked", "Ese accesorio se desbloquea al evolucionar");
        }
        const flag = (k) => (b[k] === undefined ? r[k] : b[k] ? 1 : 0);
        const hrs = r.rest_mode ? 0 : Math.max(0, (now - r.updated_at) / 36e5);
        await env.DB.prepare("UPDATE nv_pets SET name=?,accessory=?,show_on_profile=?,reminders=?,rest_mode=?,energy=?,joy=?,updated_at=? WHERE user_id=?")
          .bind(name, acc, flag("show_on_profile"), flag("reminders"), flag("rest_mode"), Math.round(decay(r.energy, hrs)), Math.round(decay(r.joy, hrs)), now, me.id).run();
        return out({ pet: petView(await getPet(env, me.id, now), now) });
      }
      if (p === "/api/pet" && m === "DELETE") {
        await env.DB.prepare("DELETE FROM nv_pets WHERE user_id=?").bind(me.id).run();
        return out({ ok: true });
      }

      // ---- Publicaciones
      if (p === "/api/posts" && m === "GET") {
        const sp = url.searchParams, kind = sp.get("kind");
        const posts = await listPosts(env, me, {
          user: (sp.get("user") || "").toLowerCase() || null, before: Number(sp.get("before")) || null,
          kind: ["image", "video", "media"].includes(kind) ? kind : null, pub: sp.get("public") === "1", following: sp.get("scope") === "following",
        });
        return out({ posts });
      }
      if (p === "/api/posts" && m === "POST") {
        if (!(await limit(env, "post:" + me.id, 20, 3600))) return fail(429, "rate_limited", "Has publicado demasiado. Inténtalo en un rato");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const text = String(b.body || "").trim(), vis = b.visibility === "private" ? "private" : "public";
        const ids = Array.isArray(b.media) ? b.media.map(String) : [];
        if (ids.length > 10 || new Set(ids).size !== ids.length || ids.some((x) => !UUID.test(x))) return fail(400, "invalid_media", "Puedes adjuntar hasta 10 fotos o 1 video");
        if ((!text && !ids.length) || text.length > 500) return fail(400, "invalid_body", "Escribe un texto (máximo 500 caracteres) o adjunta una foto o video");
        let rows = [];
        if (ids.length) {
          const { results } = await env.DB.prepare(`SELECT id,kind FROM nv_media WHERE user_id=? AND attached=0 AND id IN (${qs(ids)})`).bind(me.id, ...ids).all();
          const byId = Object.fromEntries(results.map((r) => [r.id, r]));
          rows = ids.map((x) => byId[x]);
          const vids = rows.filter((r) => r && r.kind === "video").length;
          if (rows.some((r) => !r) || (vids && (vids > 1 || rows.length > 1))) return fail(400, "invalid_media", "Los archivos no son válidos: usa hasta 10 fotos, o un solo video");
        }
        const id = crypto.randomUUID(), now = Date.now();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO nv_posts (id,user_id,body,visibility,created_at) VALUES (?,?,?,?,?)").bind(id, me.id, text, vis, now),
          ...rows.map((r, i) => env.DB.prepare("INSERT INTO nv_post_media (post_id,media_id,pos) VALUES (?,?,?)").bind(id, r.id, i)),
          ...rows.map((r) => env.DB.prepare("UPDATE nv_media SET attached=1 WHERE id=?").bind(r.id)),
        ]);
        return out({ post: { id, body: text, visibility: vis, created_at: now, username: me.username, display_name: me.display_name, avatar_id: me.avatar_id || null, like_count: 0, liked: false, saved: false, mine: true, media: rows.map((r) => ({ id: r.id, kind: r.kind })) } }, 201);
      }
      if ((mt = p.match(/^\/api\/posts\/([0-9a-f-]{36})$/)) && m === "GET") {
        const [post] = await listPosts(env, me, { id: mt[1] });
        return post ? out({ post }) : fail(404, "not_found", "La publicación no existe");
      }
      if ((mt = p.match(/^\/api\/posts\/([0-9a-f-]{36})\/(like|save)$/)) && m === "POST") {
        if (!(await limit(env, "act:" + me.id, 120, 60))) return fail(429, "rate_limited", "Demasiadas acciones seguidas");
        const ok = await visiblePost(env, me, mt[1]);
        if (!ok) return fail(404, "not_found", "La publicación no existe");
        const t = mt[2] === "like" ? "nv_likes" : "nv_saves";
        const had = await env.DB.prepare(`SELECT 1 FROM ${t} WHERE post_id=? AND user_id=?`).bind(mt[1], me.id).first();
        await env.DB.prepare(had ? `DELETE FROM ${t} WHERE post_id=? AND user_id=?` : `INSERT INTO ${t} (post_id,user_id) VALUES (?,?)`).bind(mt[1], me.id).run();
        if (mt[2] === "save") return out({ saved: !had });
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM nv_likes WHERE post_id=?").bind(mt[1]).first();
        return out({ liked: !had, like_count: c.n });
      }
      if ((mt = p.match(/^\/api\/posts\/([0-9a-f-]{36})$/)) && m === "DELETE") {
        if (!(await env.DB.prepare("SELECT 1 FROM nv_posts WHERE id=? AND user_id=?").bind(mt[1], me.id).first())) return fail(404, "not_found", "La publicación no existe o no es tuya");
        const { results: files } = await env.DB.prepare("SELECT m.id,m.key FROM nv_post_media pm JOIN nv_media m ON m.id=pm.media_id WHERE pm.post_id=?").bind(mt[1]).all();
        if (env.MEDIA && files.length) await env.MEDIA.delete(files.map((f) => f.key));
        await env.DB.batch([
          env.DB.prepare("DELETE FROM nv_likes WHERE post_id=?").bind(mt[1]), env.DB.prepare("DELETE FROM nv_saves WHERE post_id=?").bind(mt[1]),
          env.DB.prepare("DELETE FROM nv_post_media WHERE post_id=?").bind(mt[1]),
          env.DB.prepare("DELETE FROM nv_comment_likes WHERE comment_id IN (SELECT id FROM nv_comments WHERE post_id=?)").bind(mt[1]),
          env.DB.prepare("DELETE FROM nv_comment_reports WHERE comment_id IN (SELECT id FROM nv_comments WHERE post_id=?)").bind(mt[1]),
          env.DB.prepare("DELETE FROM nv_comments WHERE post_id=?").bind(mt[1]),
          ...files.map((f) => env.DB.prepare("DELETE FROM nv_media WHERE id=?").bind(f.id)),
          env.DB.prepare("DELETE FROM nv_posts WHERE id=?").bind(mt[1]),
        ]);
        return out({ ok: true });
      }

      // ---- Ajustes y seguridad
      if (p === "/api/settings" && m === "GET") return out({ settings: await getSettings(env, me.id) });
      if (p === "/api/settings" && m === "PATCH") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const next = await getSettings(env, me.id);
        if (b.default_visibility !== undefined) {
          if (!["public", "private"].includes(b.default_visibility)) return fail(400, "invalid_setting", "Valor no válido");
          next.default_visibility = b.default_visibility;
        }
        for (const k of SETTING_FLAGS) if (b[k] !== undefined) next[k] = !!b[k];
        const was = (await getSettings(env, me.id)).private_account;
        let privChanged = false;
        if (b.private_account !== undefined) {
          if (!b.private_account && ageOf(me.birth_year) < 16) return fail(403, "minor_private", "Por seguridad, las cuentas de menores de 16 años son privadas");
          next.private_account = !!b.private_account; privChanged = true;
        }
        if (b.msg_who !== undefined) {
          if (!["everyone", "following", "nobody"].includes(b.msg_who)) return fail(400, "invalid_setting", "Valor no válido");
          if (b.msg_who === "everyone" && ageOf(me.birth_year) < 18) return fail(403, "minor_msg", "Por seguridad, solo las personas que sigues pueden escribirte");
          next.msg_who = b.msg_who; privChanged = true;
        }
        await env.DB.prepare("INSERT INTO nv_settings (user_id,default_visibility,orya_posts,notif_likes,notif_comments,notif_follows) VALUES (?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET default_visibility=excluded.default_visibility,orya_posts=excluded.orya_posts,notif_likes=excluded.notif_likes,notif_comments=excluded.notif_comments,notif_follows=excluded.notif_follows")
          .bind(me.id, next.default_visibility, +next.orya_posts, +next.notif_likes, +next.notif_comments, +next.notif_follows).run();
        if (privChanged) {
          await env.DB.prepare("INSERT INTO nv_privacy (user_id,private_account,msg_who) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET private_account=excluded.private_account,msg_who=excluded.msg_who").bind(me.id, +next.private_account, next.msg_who).run();
          if (was && !next.private_account) await env.DB.prepare("UPDATE nv_follows SET status='accepted' WHERE followee_id=? AND status='pending'").bind(me.id).run();
        }
        return out({ settings: next });
      }
      if (p === "/api/me/password" && m === "POST") {
        if (!(await limit(env, "pw:" + me.id, 5, 900))) return fail(429, "rate_limited", "Demasiados intentos. Espera unos minutos");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const cur = String(b.current || "").slice(0, 128), nw = String(b.next || "");
        if (nw.length < 8 || nw.length > 128) return fail(400, "invalid_password", "La contraseña nueva debe tener entre 8 y 128 caracteres");
        const row = await env.DB.prepare("SELECT pass_hash,pass_salt FROM nv_users WHERE id=?").bind(me.id).first();
        if (!same(await pbkdf2(cur, row.pass_salt), row.pass_hash)) return fail(403, "invalid_credentials", "La contraseña actual no es correcta");
        if (nw === cur) return fail(400, "same_password", "La contraseña nueva debe ser distinta a la actual");
        const salt = rand(16), hash = await pbkdf2(nw, salt), keep = await sha(req.headers.get("Authorization").slice(7));
        await env.DB.batch([
          env.DB.prepare("UPDATE nv_users SET pass_hash=?, pass_salt=? WHERE id=?").bind(hash, salt, me.id),
          env.DB.prepare("DELETE FROM nv_sessions WHERE user_id=? AND token_hash<>?").bind(me.id, keep),
        ]);
        return out({ ok: true });
      }
      if (p === "/api/auth/logout_all" && m === "POST") {
        await env.DB.prepare("DELETE FROM nv_sessions WHERE user_id=?").bind(me.id).run();
        return out({ ok: true });
      }
      if (p === "/api/me/export" && m === "GET") {
        if (!(await limit(env, "exp:" + me.id, 3, 3600))) return fail(429, "rate_limited", "Ya descargaste tus datos varias veces. Inténtalo más tarde");
        const q = async (sql) => (await env.DB.prepare(sql).bind(me.id).all()).results;
        return out({
          exportado_el: new Date().toISOString(), perfil: pub(me), cuenta_creada: me.created_at, ajustes: await getSettings(env, me.id),
          publicaciones: await q("SELECT id,body,visibility,created_at FROM nv_posts WHERE user_id=? ORDER BY created_at"),
          archivos: await q("SELECT m.id,m.kind,m.mime,m.size,pm.post_id FROM nv_media m LEFT JOIN nv_post_media pm ON pm.media_id=m.id WHERE m.user_id=?"),
          me_gusta: (await q("SELECT post_id FROM nv_likes WHERE user_id=?")).map((r) => r.post_id),
          guardados: (await q("SELECT post_id FROM nv_saves WHERE user_id=?")).map((r) => r.post_id),
          mascota: (await q("SELECT status,species,name,xp,accessory,requested_at,hatched_at FROM nv_pets WHERE user_id=?"))[0] || null,
          bloqueados: (await q("SELECT u.username FROM nv_blocks b JOIN nv_users u ON u.id=b.blocked WHERE b.blocker=?")).map((r) => r.username),
          historias: await q("SELECT id,text,visibility,created_at,expires_at FROM nv_stories WHERE user_id=? ORDER BY created_at"),
          destacadas: await q("SELECT id,title,created_at FROM nv_highlights WHERE user_id=?"),
          siguiendo: (await q("SELECT u.username FROM nv_follows f JOIN nv_users u ON u.id=f.followee_id WHERE f.follower_id=? AND f.status='accepted'")).map((r) => r.username),
          seguidores: (await q("SELECT u.username FROM nv_follows f JOIN nv_users u ON u.id=f.follower_id WHERE f.followee_id=? AND f.status='accepted'")).map((r) => r.username),
          comentarios: await q("SELECT id,post_id,body,created_at FROM nv_comments WHERE user_id=? ORDER BY created_at"),
          denuncias_enviadas: await q("SELECT target_type,reason,created_at FROM nv_reports WHERE reporter_id=?"),
        });
      }

      // ---- Bloqueos
      if (p === "/api/blocks" && m === "GET") {
        const { results } = await env.DB.prepare("SELECT u.username,u.display_name,pr.avatar_id FROM nv_blocks b JOIN nv_users u ON u.id=b.blocked LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE b.blocker=? ORDER BY b.created_at DESC").bind(me.id).all();
        return out({ blocks: results.map((r) => ({ ...r, avatar_id: r.avatar_id || null })) });
      }
      if (p === "/api/blocks" && m === "POST") {
        if (!(await limit(env, "blk:" + me.id, 60, 3600))) return fail(429, "rate_limited", "Demasiadas acciones seguidas");
        const b = await readBody(req), target = b && (await env.DB.prepare("SELECT id FROM nv_users WHERE username=?").bind(String(b.username || "").toLowerCase()).first());
        if (!target) return fail(404, "not_found", "Ese usuario no existe");
        if (target.id === me.id) return fail(400, "self", "No puedes bloquearte a ti mismo");
        await env.DB.batch([
          env.DB.prepare("INSERT OR IGNORE INTO nv_blocks (blocker,blocked,created_at) VALUES (?,?,?)").bind(me.id, target.id, Date.now()),
          env.DB.prepare("DELETE FROM nv_follows WHERE (follower_id=? AND followee_id=?) OR (follower_id=? AND followee_id=?)").bind(me.id, target.id, target.id, me.id),
          env.DB.prepare("DELETE FROM nv_streaks WHERE (user_a=? AND user_b=?)").bind(...pairKey(me.id, target.id)),
        ]);
        return out({ ok: true });
      }
      if ((mt = p.match(/^\/api\/blocks\/([A-Za-z0-9_.]{3,24})$/)) && m === "DELETE") {
        const target = await env.DB.prepare("SELECT id FROM nv_users WHERE username=?").bind(mt[1].toLowerCase()).first();
        if (target) await env.DB.prepare("DELETE FROM nv_blocks WHERE blocker=? AND blocked=?").bind(me.id, target.id).run();
        return out({ ok: true });
      }

      // ---- Denuncias (las revisa una persona del equipo; la otra parte nunca recibe aviso)
      if (p === "/api/reports" && m === "POST") {
        if (!(await limit(env, "rep:" + me.id, 20, 3600))) return fail(429, "rate_limited", "Has enviado muchas denuncias seguidas. Inténtalo más tarde");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const type = b.type, reason = String(b.reason || ""), details = String(b.details || "").trim();
        if (!["post", "user", "app", "comment"].includes(type) || !Object.hasOwn(REASONS, reason) || (type !== "app" && reason === "bug")) return fail(400, "invalid_report", "Elige un motivo válido");
        if (details.length > 500) return fail(400, "invalid_details", "Los detalles admiten hasta 500 caracteres");
        if (type === "comment") {
          const cc = await commentCtx(env, me, String(b.target || ""));
          if (!cc) return fail(404, "not_found", "El comentario no existe");
          if (cc.user_id === me.id) return fail(400, "self", "No puedes denunciar tu propio comentario");
          if (await env.DB.prepare("SELECT 1 FROM nv_comment_reports WHERE reporter_id=? AND comment_id=?").bind(me.id, cc.id).first()) return out({ ok: true, duplicate: true });
          await env.DB.prepare("INSERT INTO nv_comment_reports (id,reporter_id,comment_id,reason,details,priority,created_at) VALUES (?,?,?,?,?,?,?)").bind(crypto.randomUUID(), me.id, cc.id, reason, details, REASONS[reason], Date.now()).run();
          return out({ ok: true, duplicate: false }, 201);
        }
        let target = crypto.randomUUID();
        if (type === "post") {
          const id = String(b.target || "");
          const post = UUID.test(id) && (await visiblePost(env, me, id));
          if (!post) return fail(404, "not_found", "La publicación no existe");
          if (post.user_id === me.id) return fail(400, "self", "No puedes denunciar tu propia publicación");
          target = id;
        } else if (type === "user") {
          const u = await env.DB.prepare("SELECT id FROM nv_users WHERE username=?").bind(String(b.target || "").toLowerCase()).first();
          if (!u) return fail(404, "not_found", "Ese usuario no existe");
          if (u.id === me.id) return fail(400, "self", "No puedes denunciarte a ti mismo");
          target = u.id;
        }
        if (await env.DB.prepare("SELECT 1 FROM nv_reports WHERE reporter_id=? AND target_type=? AND target_id=?").bind(me.id, type, target).first()) return out({ ok: true, duplicate: true });
        await env.DB.prepare("INSERT INTO nv_reports (id,reporter_id,target_type,target_id,reason,details,priority,created_at) VALUES (?,?,?,?,?,?,?,?)")
          .bind(crypto.randomUUID(), me.id, type, target, reason, details, REASONS[reason], Date.now()).run();
        return out({ ok: true, duplicate: false }, 201);
      }

      // ---- Historias (24 h)
      if (p === "/api/stories" && m === "POST") {
        if (!(await limit(env, "story:" + me.id, 30, 86400))) return fail(429, "rate_limited", "Has publicado muchas historias hoy");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const text = String(b.text || "").trim(), bg = b.bg === undefined ? "violet" : String(b.bg), vis = b.visibility === "private" ? "private" : "public";
        if (text.length > 200) return fail(400, "invalid_text", "El texto admite hasta 200 caracteres");
        if (!ACCENTS.includes(bg)) return fail(400, "invalid_bg", "Color no válido");
        let mid = null;
        if (b.media) {
          mid = String(b.media);
          if (!UUID.test(mid) || !(await env.DB.prepare("SELECT 1 FROM nv_media WHERE id=? AND user_id=? AND attached=0").bind(mid, me.id).first())) return fail(400, "invalid_media", "La foto o el video no es válido");
        }
        if (!mid && !text) return fail(400, "empty_story", "Añade una foto, un video o un texto");
        const id = crypto.randomUUID(), now = Date.now();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO nv_stories (id,user_id,media_id,text,bg,visibility,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)").bind(id, me.id, mid, text, bg, vis, now, now + 864e5),
          ...(mid ? [env.DB.prepare("UPDATE nv_media SET attached=1 WHERE id=?").bind(mid)] : []),
        ]);
        const { results: old } = await env.DB.prepare("SELECT s.id,s.media_id,m.key FROM nv_stories s LEFT JOIN nv_media m ON m.id=s.media_id WHERE s.created_at<? AND NOT EXISTS (SELECT 1 FROM nv_highlight_items i WHERE i.story_id=s.id) LIMIT 20").bind(now - 30 * 864e5).all();
        await purgeStories(env, old);
        return out({ story: shapeStory({ ...(await env.DB.prepare(STORY_SQL + " WHERE s.id=?2").bind(me.id, id).first()) }) }, 201);
      }
      if (p === "/api/stories" && m === "GET") {
        const { results } = await env.DB.prepare(STORY_SQL + ` WHERE s.expires_at>?2 AND (s.user_id=?1 OR (s.visibility='public' AND ${FOLLOWS("?1", "s.user_id")})) AND ${NOBLOCK("?1", "s.user_id")} ORDER BY s.created_at ASC LIMIT 300`).bind(me.id, Date.now()).all();
        return out({ groups: groupStories(results, me).slice(0, 40) });
      }
      if (p === "/api/stories/archive" && m === "GET") {
        const { results } = await env.DB.prepare(STORY_SQL + " WHERE s.user_id=?1 ORDER BY s.created_at DESC LIMIT 60").bind(me.id).all();
        const ids = results.map((r) => r.id), hl = new Set();
        if (ids.length) for (const x of (await env.DB.prepare(`SELECT DISTINCT story_id FROM nv_highlight_items WHERE story_id IN (${qs(ids)})`).bind(...ids).all()).results) hl.add(x.story_id);
        const now = Date.now();
        return out({ stories: results.map((r) => ({ ...shapeStory(r), active: r.expires_at > now, highlighted: hl.has(r.id) })) });
      }
      if ((mt = p.match(/^\/api\/stories\/user\/([A-Za-z0-9_.]{3,24})$/)) && m === "GET") {
        const u = await env.DB.prepare("SELECT id FROM nv_users WHERE username=?").bind(mt[1].toLowerCase()).first();
        if (!u) return fail(404, "not_found", "Ese usuario no existe");
        const { results } = await env.DB.prepare(STORY_SQL + ` WHERE s.user_id=?4 AND s.expires_at>?2 AND (s.user_id=?1 OR (s.visibility='public' AND ${CANSEE("?1", "s.user_id")})) AND ${NOBLOCK("?1", "s.user_id")} ORDER BY s.created_at ASC`).bind(me.id, Date.now(), 0, u.id).all();
        return out({ stories: results.map(shapeStory), all_seen: results.every((r) => r.seen) });
      }
      if ((mt = p.match(/^\/api\/stories\/([0-9a-f-]{36})\/(view|react|reply|activity)$/))) {
        const id = mt[1], act = mt[2], now = Date.now();
        if (act === "activity" && m === "GET") {
          if (!(await env.DB.prepare("SELECT 1 FROM nv_stories WHERE id=? AND user_id=?").bind(id, me.id).first())) return fail(404, "not_found", "La historia no existe o no es tuya");
          const { results: views } = await env.DB.prepare("SELECT u.username,u.display_name,pr.avatar_id,v.viewed_at,(SELECT emoji FROM nv_story_reactions r WHERE r.story_id=v.story_id AND r.user_id=v.viewer_id) AS reaction FROM nv_story_views v JOIN nv_users u ON u.id=v.viewer_id LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE v.story_id=? ORDER BY v.viewed_at DESC LIMIT 200").bind(id).all();
          const { results: replies } = await env.DB.prepare("SELECT rp.id,u.username,u.display_name,pr.avatar_id,rp.text,rp.created_at FROM nv_story_replies rp JOIN nv_users u ON u.id=rp.from_id LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE rp.story_id=? ORDER BY rp.created_at DESC LIMIT 200").bind(id).all();
          return out({ views: views.map((v) => ({ ...v, avatar_id: v.avatar_id || null, reaction: v.reaction || null })), replies: replies.map((r) => ({ ...r, avatar_id: r.avatar_id || null })), view_count: views.length, reaction_count: views.filter((v) => v.reaction).length });
        }
        if (act !== "activity" && m === "POST") {
          if (!(await limit(env, "sact:" + me.id, 300, 3600))) return fail(429, "rate_limited", "Demasiadas acciones seguidas");
          const st = await visibleStory(env, me, id, now);
          if (!st) return fail(404, "not_found", "La historia no existe o ya caducó");
          const own = st.user_id === me.id;
          if (act === "view") {
            if (!own) await env.DB.prepare("INSERT OR IGNORE INTO nv_story_views (story_id,viewer_id,viewed_at) VALUES (?,?,?)").bind(id, me.id, now).run();
            return out({ ok: true });
          }
          if (own) return fail(400, "self", "No puedes hacerlo en tu propia historia");
          const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
          if (act === "react") {
            if (b.emoji === null || b.emoji === "") { await env.DB.prepare("DELETE FROM nv_story_reactions WHERE story_id=? AND user_id=?").bind(id, me.id).run(); return out({ ok: true, my_reaction: null }); }
            if (!EMOJIS.includes(b.emoji)) return fail(400, "invalid_emoji", "Reacción no válida");
            await env.DB.batch([
              env.DB.prepare("INSERT OR IGNORE INTO nv_story_views (story_id,viewer_id,viewed_at) VALUES (?,?,?)").bind(id, me.id, now),
              env.DB.prepare("INSERT INTO nv_story_reactions (story_id,user_id,emoji,created_at) VALUES (?,?,?,?) ON CONFLICT(story_id,user_id) DO UPDATE SET emoji=excluded.emoji,created_at=excluded.created_at").bind(id, me.id, b.emoji, now),
            ]);
            return out({ ok: true, my_reaction: b.emoji });
          }
          const text = String(b.text || "").trim();
          if (!text || text.length > 300) return fail(400, "invalid_text", "Escribe una respuesta de hasta 300 caracteres");
          if (!(await limit(env, "sreply:" + me.id, 30, 3600))) return fail(429, "rate_limited", "Has enviado muchas respuestas seguidas");
          await env.DB.prepare("INSERT INTO nv_story_replies (id,story_id,from_id,text,created_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), id, me.id, text, now).run();
          return out({ ok: true }, 201);
        }
      }
      if ((mt = p.match(/^\/api\/stories\/([0-9a-f-]{36})$/)) && m === "DELETE") {
        const st = await env.DB.prepare("SELECT s.id,s.media_id,m.key FROM nv_stories s LEFT JOIN nv_media m ON m.id=s.media_id WHERE s.id=? AND s.user_id=?").bind(mt[1], me.id).first();
        if (!st) return fail(404, "not_found", "La historia no existe o no es tuya");
        await purgeStories(env, [st]);
        return out({ ok: true });
      }

      // ---- Destacadas
      if ((mt = p.match(/^\/api\/users\/([A-Za-z0-9_.]{3,24})\/highlights$/)) && m === "GET") {
        const u = await env.DB.prepare("SELECT id FROM nv_users WHERE username=?").bind(mt[1].toLowerCase()).first();
        if (!u || (u.id !== me.id && (await env.DB.prepare("SELECT 1 FROM nv_blocks WHERE (blocker=? AND blocked=?) OR (blocker=? AND blocked=?)").bind(me.id, u.id, u.id, me.id).first()))) return fail(404, "not_found", "Ese usuario no existe");
        if (!(await canSeeUser(env, me, u.id))) return out({ highlights: [] });
        const first = (col) => `(SELECT ${col} FROM nv_highlight_items i JOIN nv_stories s ON s.id=i.story_id LEFT JOIN nv_media md ON md.id=s.media_id WHERE i.highlight_id=h.id ORDER BY i.pos LIMIT 1)`;
        const { results } = await env.DB.prepare(`SELECT h.id,h.title,h.created_at,(SELECT COUNT(*) FROM nv_highlight_items i WHERE i.highlight_id=h.id) AS n,${first("s.media_id")} AS cover_media,${first("md.kind")} AS cover_kind,${first("s.bg")} AS cover_bg FROM nv_highlights h WHERE h.user_id=? ORDER BY h.created_at DESC`).bind(u.id).all();
        return out({ highlights: results.map((h) => ({ id: h.id, title: h.title, count: h.n, cover: h.cover_media ? { id: h.cover_media, kind: h.cover_kind } : null, bg: h.cover_bg || "violet" })) });
      }
      if (p === "/api/highlights" && m === "POST") {
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const title = String(b.title || "").trim(), ids = Array.isArray(b.stories) ? b.stories.map(String) : [];
        if (title.length < 1 || title.length > 20) return fail(400, "invalid_title", "El título debe tener entre 1 y 20 caracteres");
        if (!ids.length || ids.length > 30 || new Set(ids).size !== ids.length || ids.some((x) => !UUID.test(x))) return fail(400, "invalid_stories", "Elige entre 1 y 30 historias");
        if ((await env.DB.prepare("SELECT COUNT(*) AS n FROM nv_highlights WHERE user_id=?").bind(me.id).first()).n >= 20) return fail(400, "too_many", "Puedes tener hasta 20 destacadas");
        const own = await env.DB.prepare(`SELECT id FROM nv_stories WHERE user_id=? AND id IN (${qs(ids)})`).bind(me.id, ...ids).all();
        if (own.results.length !== ids.length) return fail(400, "invalid_stories", "Solo puedes destacar tus propias historias");
        const id = crypto.randomUUID();
        await env.DB.batch([env.DB.prepare("INSERT INTO nv_highlights (id,user_id,title,created_at) VALUES (?,?,?,?)").bind(id, me.id, title, Date.now()), ...ids.map((x, i) => env.DB.prepare("INSERT INTO nv_highlight_items (highlight_id,story_id,pos) VALUES (?,?,?)").bind(id, x, i))]);
        return out({ highlight: { id, title, count: ids.length } }, 201);
      }
      if ((mt = p.match(/^\/api\/highlights\/([0-9a-f-]{36})$/))) {
        const h = await env.DB.prepare("SELECT h.id,h.title,h.user_id,u.username,u.display_name FROM nv_highlights h JOIN nv_users u ON u.id=h.user_id WHERE h.id=?").bind(mt[1]).first();
        const hidden = !h || (h.user_id !== me.id && (await env.DB.prepare("SELECT 1 FROM nv_blocks WHERE (blocker=? AND blocked=?) OR (blocker=? AND blocked=?)").bind(me.id, h.user_id, h.user_id, me.id).first()));
        if (hidden || !(await canSeeUser(env, me, h.user_id))) return fail(404, "not_found", "La destacada no existe");
        if (m === "GET") {
          const { results } = await env.DB.prepare(STORY_SQL + " JOIN nv_highlight_items hi ON hi.story_id=s.id WHERE hi.highlight_id=?2 ORDER BY hi.pos").bind(me.id, h.id).all();
          return out({ highlight: { id: h.id, title: h.title, username: h.username, display_name: h.display_name, is_me: h.user_id === me.id }, stories: results.map(shapeStory) });
        }
        if (h.user_id !== me.id) return fail(404, "not_found", "La destacada no existe");
        if (m === "DELETE") {
          await env.DB.batch([env.DB.prepare("DELETE FROM nv_highlight_items WHERE highlight_id=?").bind(h.id), env.DB.prepare("DELETE FROM nv_highlights WHERE id=?").bind(h.id)]);
          return out({ ok: true });
        }
        if (m === "PATCH") {
          const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
          const title = b.title === undefined ? h.title : String(b.title).trim();
          if (title.length < 1 || title.length > 20) return fail(400, "invalid_title", "El título debe tener entre 1 y 20 caracteres");
          const add = Array.isArray(b.add) ? b.add.map(String) : [], rem = Array.isArray(b.remove) ? b.remove.map(String) : [];
          if ([...add, ...rem].some((x) => !UUID.test(x))) return fail(400, "invalid_stories", "Historias no válidas");
          if (add.length) {
            const own = await env.DB.prepare(`SELECT id FROM nv_stories WHERE user_id=? AND id IN (${qs(add)})`).bind(me.id, ...add).all();
            if (own.results.length !== new Set(add).size) return fail(400, "invalid_stories", "Solo puedes destacar tus propias historias");
          }
          const cur = (await env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(MAX(pos),-1) AS mx FROM nv_highlight_items WHERE highlight_id=?").bind(h.id).first());
          const keep = (await env.DB.prepare("SELECT story_id FROM nv_highlight_items WHERE highlight_id=?").bind(h.id).all()).results.map((r) => r.story_id).filter((x) => !rem.includes(x));
          const fresh = [...new Set(add)].filter((x) => !keep.includes(x));
          if (keep.length + fresh.length < 1) return fail(400, "empty_highlight", "Una destacada necesita al menos una historia");
          if (keep.length + fresh.length > 100) return fail(400, "too_many", "Una destacada admite hasta 100 historias");
          await env.DB.batch([
            env.DB.prepare("UPDATE nv_highlights SET title=? WHERE id=?").bind(title, h.id),
            ...rem.map((x) => env.DB.prepare("DELETE FROM nv_highlight_items WHERE highlight_id=? AND story_id=?").bind(h.id, x)),
            ...fresh.map((x, i) => env.DB.prepare("INSERT OR IGNORE INTO nv_highlight_items (highlight_id,story_id,pos) VALUES (?,?,?)").bind(h.id, x, cur.mx + 1 + i)),
          ]);
          return out({ highlight: { id: h.id, title, count: keep.length + fresh.length } });
        }
      }

      // ---- Seguidores
      const byName = (name) => env.DB.prepare("SELECT id,username,display_name,birth_year FROM nv_users WHERE username=?").bind(String(name || "").toLowerCase()).first();
      const blockedPair = (uid) => env.DB.prepare("SELECT 1 FROM nv_blocks WHERE (blocker=? AND blocked=?) OR (blocker=? AND blocked=?)").bind(me.id, uid, uid, me.id).first();
      const relState = (r) => (r ? (r.status === "accepted" ? "following" : "requested") : "none");
      if (p === "/api/follows" && m === "POST") {
        if (!(await limit(env, "fol:" + me.id, 60, 3600))) return fail(429, "rate_limited", "Demasiadas acciones seguidas");
        const b = await readBody(req), t = b && (await byName(b.username));
        if (!t || (await blockedPair(t.id))) return fail(404, "not_found", "Ese usuario no existe");
        if (t.id === me.id) return fail(400, "self", "No puedes seguirte a ti mismo");
        const cur = await env.DB.prepare("SELECT status FROM nv_follows WHERE follower_id=? AND followee_id=?").bind(me.id, t.id).first();
        if (cur) return out({ state: relState(cur) });
        const pv = await env.DB.prepare("SELECT private_account AS p FROM nv_privacy WHERE user_id=?").bind(t.id).first(), st = pv && pv.p ? "pending" : "accepted";
        await env.DB.prepare("INSERT OR IGNORE INTO nv_follows (follower_id,followee_id,status,created_at) VALUES (?,?,?,?)").bind(me.id, t.id, st, Date.now()).run();
        return out({ state: relState({ status: st }) }, 201);
      }
      if ((mt = p.match(/^\/api\/follows\/([A-Za-z0-9_.]{3,24})$/)) && m === "DELETE") {
        const t = await byName(mt[1]);
        if (t) await env.DB.prepare("DELETE FROM nv_follows WHERE follower_id=? AND followee_id=?").bind(me.id, t.id).run();
        return out({ state: "none" });
      }
      if (p === "/api/follows/requests" && m === "GET") {
        const { results } = await env.DB.prepare(`SELECT u.username,u.display_name,pr.avatar_id,f.created_at FROM nv_follows f JOIN nv_users u ON u.id=f.follower_id LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE f.followee_id=? AND f.status='pending' AND NOT EXISTS (SELECT 1 FROM nv_blocks bk WHERE (bk.blocker=f.followee_id AND bk.blocked=u.id) OR (bk.blocker=u.id AND bk.blocked=f.followee_id)) ORDER BY f.created_at DESC LIMIT 100`).bind(me.id).all();
        return out({ requests: results.map((r) => ({ ...r, avatar_id: r.avatar_id || null })) });
      }
      if ((mt = p.match(/^\/api\/follows\/requests\/([A-Za-z0-9_.]{3,24})\/(accept|decline)$/)) && m === "POST") {
        const t = await byName(mt[1]);
        const row = t && (await env.DB.prepare("SELECT 1 FROM nv_follows WHERE follower_id=? AND followee_id=? AND status='pending'").bind(t.id, me.id).first());
        if (!row) return fail(404, "not_found", "No hay una solicitud de esa persona");
        await (mt[2] === "accept" ? env.DB.prepare("UPDATE nv_follows SET status='accepted' WHERE follower_id=? AND followee_id=?") : env.DB.prepare("DELETE FROM nv_follows WHERE follower_id=? AND followee_id=?")).bind(t.id, me.id).run();
        return out({ ok: true });
      }
      if ((mt = p.match(/^\/api\/followers\/([A-Za-z0-9_.]{3,24})$/)) && m === "DELETE") {
        const t = await byName(mt[1]);
        if (t) await env.DB.prepare("DELETE FROM nv_follows WHERE follower_id=? AND followee_id=?").bind(t.id, me.id).run();
        return out({ ok: true });
      }
      if ((mt = p.match(/^\/api\/users\/([A-Za-z0-9_.]{3,24})\/(followers|following)$/)) && m === "GET") {
        const t = await byName(mt[1]);
        if (!t || (await blockedPair(t.id))) return fail(404, "not_found", "Ese usuario no existe");
        if (!(await canSeeUser(env, me, t.id))) return fail(403, "private", "Esta cuenta es privada. Sígue a esta persona para ver su lista");
        const [col, other] = mt[2] === "followers" ? ["follower_id", "followee_id"] : ["followee_id", "follower_id"];
        const { results } = await env.DB.prepare(`SELECT u.id AS uid,u.username,u.display_name,pr.avatar_id,(SELECT status FROM nv_follows m2 WHERE m2.follower_id=?1 AND m2.followee_id=u.id) AS rel FROM nv_follows f JOIN nv_users u ON u.id=f.${col} LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE f.${other}=?2 AND f.status='accepted' AND NOT EXISTS (SELECT 1 FROM nv_blocks bk WHERE (bk.blocker=?1 AND bk.blocked=u.id) OR (bk.blocker=u.id AND bk.blocked=?1)) ORDER BY f.created_at DESC LIMIT 100`).bind(me.id, t.id).all();
        return out({ users: results.map((r) => ({ username: r.username, display_name: r.display_name, avatar_id: r.avatar_id || null, follow_state: r.uid === me.id ? "self" : relState(r.rel ? { status: r.rel } : null) })) });
      }

      // ---- Comentarios
      const CSQL = `SELECT c.id,c.post_id,c.parent_id,c.body,c.created_at,c.user_id,u.username,u.display_name,pr.avatar_id,
        (SELECT COUNT(*) FROM nv_comment_likes l WHERE l.comment_id=c.id) AS like_count,
        EXISTS(SELECT 1 FROM nv_comment_likes l WHERE l.comment_id=c.id AND l.user_id=?1) AS liked,
        (SELECT COUNT(*) FROM nv_comments r WHERE r.parent_id=c.id) AS reply_count,
        (SELECT user_id FROM nv_posts po WHERE po.id=c.post_id) AS post_owner
        FROM nv_comments c JOIN nv_users u ON u.id=c.user_id LEFT JOIN nv_profiles pr ON pr.user_id=u.id`;
      const NOBLK_C = "NOT EXISTS (SELECT 1 FROM nv_blocks bk WHERE (bk.blocker=?1 AND bk.blocked=c.user_id) OR (bk.blocker=c.user_id AND bk.blocked=?1))";
      const shapeC = (r) => ({ id: r.id, post_id: r.post_id, parent_id: r.parent_id, body: r.body, created_at: r.created_at, username: r.username, display_name: r.display_name, avatar_id: r.avatar_id || null, like_count: r.like_count, liked: !!r.liked, reply_count: r.reply_count, mine: r.user_id === me.id, can_delete: r.user_id === me.id || r.post_owner === me.id });
      if ((mt = p.match(/^\/api\/posts\/([0-9a-f-]{36})\/comments$/)) && m === "GET") {
        if (!(await visiblePost(env, me, mt[1]))) return fail(404, "not_found", "La publicación no existe");
        const before = Number(url.searchParams.get("before")) || null;
        const { results } = await env.DB.prepare(CSQL + ` WHERE c.post_id=?2 AND c.parent_id IS NULL AND (?3 IS NULL OR c.created_at<?3) AND ${NOBLK_C} ORDER BY c.created_at DESC LIMIT 30`).bind(me.id, mt[1], before).all();
        return out({ comments: results.map(shapeC) });
      }
      if ((mt = p.match(/^\/api\/comments\/([0-9a-f-]{36})\/replies$/)) && m === "GET") {
        const cc = await commentCtx(env, me, mt[1]);
        if (!cc) return fail(404, "not_found", "El comentario no existe");
        const { results } = await env.DB.prepare(CSQL + ` WHERE c.parent_id=?2 AND ${NOBLK_C} ORDER BY c.created_at ASC LIMIT 100`).bind(me.id, cc.id).all();
        return out({ comments: results.map(shapeC) });
      }
      if ((mt = p.match(/^\/api\/posts\/([0-9a-f-]{36})\/comments$/)) && m === "POST") {
        if (!(await limit(env, "cmt:" + me.id, 30, 3600))) return fail(429, "rate_limited", "Has comentado mucho. Inténtalo en un rato");
        if (!(await visiblePost(env, me, mt[1]))) return fail(404, "not_found", "La publicación no existe");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const text = String(b.body || "").trim(), parent = b.parent ? String(b.parent) : null;
        if (!text || text.length > 300) return fail(400, "invalid_body", "Escribe un comentario de hasta 300 caracteres");
        if (parent && !(UUID.test(parent) && (await env.DB.prepare("SELECT 1 FROM nv_comments WHERE id=? AND post_id=? AND parent_id IS NULL").bind(parent, mt[1]).first()))) return fail(400, "invalid_parent", "Solo se puede responder a un comentario principal");
        const id = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO nv_comments (id,post_id,user_id,parent_id,body,created_at) VALUES (?,?,?,?,?,?)").bind(id, mt[1], me.id, parent, text, Date.now()).run();
        const row = await env.DB.prepare(CSQL + " WHERE c.id=?2").bind(me.id, id).first();
        return out({ comment: shapeC(row) }, 201);
      }
      if ((mt = p.match(/^\/api\/comments\/([0-9a-f-]{36})$/)) && m === "DELETE") {
        const cc = await commentCtx(env, me, mt[1]);
        if (!cc || (cc.user_id !== me.id && cc.post_owner !== me.id)) return fail(404, "not_found", "El comentario no existe o no puedes borrarlo");
        const sub = "(SELECT id FROM nv_comments WHERE id=?1 OR parent_id=?1)";
        await env.DB.batch([
          env.DB.prepare(`DELETE FROM nv_comment_likes WHERE comment_id IN ${sub}`).bind(cc.id), env.DB.prepare(`DELETE FROM nv_comment_reports WHERE comment_id IN ${sub}`).bind(cc.id),
          env.DB.prepare("DELETE FROM nv_comments WHERE id=?1 OR parent_id=?1").bind(cc.id),
        ]);
        return out({ ok: true });
      }
      if ((mt = p.match(/^\/api\/comments\/([0-9a-f-]{36})\/like$/)) && m === "POST") {
        if (!(await limit(env, "act:" + me.id, 120, 60))) return fail(429, "rate_limited", "Demasiadas acciones seguidas");
        const cc = await commentCtx(env, me, mt[1]);
        if (!cc) return fail(404, "not_found", "El comentario no existe");
        const had = await env.DB.prepare("SELECT 1 FROM nv_comment_likes WHERE comment_id=? AND user_id=?").bind(cc.id, me.id).first();
        await env.DB.prepare(had ? "DELETE FROM nv_comment_likes WHERE comment_id=? AND user_id=?" : "INSERT INTO nv_comment_likes (comment_id,user_id) VALUES (?,?)").bind(cc.id, me.id).run();
        return out({ liked: !had, like_count: (await env.DB.prepare("SELECT COUNT(*) AS n FROM nv_comment_likes WHERE comment_id=?").bind(cc.id).first()).n });
      }

      // ---- Mensajes
      const memberOf = (cid) => env.DB.prepare("SELECT c.id,c.kind,c.title,c.direct_key,m.role,m.last_read_at FROM nv_convs c JOIN nv_conv_members m ON m.conv_id=c.id WHERE c.id=? AND m.user_id=?").bind(cid, me.id).first();
      const membersOf = async (cid) => (await env.DB.prepare("SELECT u.id,u.username,u.display_name,pr.avatar_id,cm.role,cm.last_read_at FROM nv_conv_members cm JOIN nv_users u ON u.id=cm.user_id LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE cm.conv_id=? ORDER BY cm.joined_at").bind(cid).all()).results;
      const streakFor = async (otherId) => {
        const [a, b] = pairKey(me.id, otherId), s = await env.DB.prepare("SELECT * FROM nv_streaks WHERE user_a=? AND user_b=?").bind(a, b).first();
        if (!s) return null;
        const today = dayOf(Date.now()), meCol = me.id === a ? s.a_last : s.b_last, thCol = me.id === a ? s.b_last : s.a_last;
        return { status: s.status, proposed_by_me: s.proposed_by === me.id, count: s.count, best: s.best, total_days: s.total_days, paused: !!s.paused, me_today: meCol === today, they_today: thCol === today };
      };
      if (p === "/api/conversations" && m === "GET") {
        const { results: mine } = await env.DB.prepare("SELECT c.id,c.kind,c.title,c.updated_at,m.last_read_at FROM nv_conv_members m JOIN nv_convs c ON c.id=m.conv_id WHERE m.user_id=? ORDER BY c.updated_at DESC LIMIT 50").bind(me.id).all();
        const list = [];
        for (const c of mine) {
          const mem = await membersOf(c.id), others = mem.filter((x) => x.id !== me.id);
          if (c.kind === "direct" && others[0] && (await blockedPair(others[0].id))) continue;
          const last = await env.DB.prepare("SELECT m.body,m.post_id,m.deleted,m.created_at,u.username AS sender FROM nv_messages m JOIN nv_users u ON u.id=m.sender_id WHERE m.conv_id=? ORDER BY m.created_at DESC LIMIT 1").bind(c.id).first();
          const unread = (await env.DB.prepare("SELECT COUNT(*) AS n FROM nv_messages WHERE conv_id=? AND sender_id<>? AND created_at>? AND deleted=0").bind(c.id, me.id, c.last_read_at).first()).n;
          list.push({ id: c.id, kind: c.kind, title: c.kind === "direct" ? (others[0] ? others[0].display_name : "Conversación") : c.title, with: c.kind === "direct" && others[0] ? { username: others[0].username, avatar_id: others[0].avatar_id || null } : null,
            members: others.slice(0, 4).map((x) => ({ username: x.username, display_name: x.display_name, avatar_id: x.avatar_id || null })), member_count: mem.length, unread,
            last: last ? { text: last.deleted ? "Mensaje eliminado" : last.post_id ? "Compartió una publicación" : last.body, sender: last.sender, mine: last.sender === me.username, created_at: last.created_at } : null, updated_at: c.updated_at,
            streak: c.kind === "direct" && others[0] ? await streakFor(others[0].id) : null });
        }
        return out({ conversations: list, unread_total: list.reduce((n, c) => n + c.unread, 0) });
      }
      if (p === "/api/conversations" && m === "POST") {
        if (!(await limit(env, "conv:" + me.id, 30, 3600))) return fail(429, "rate_limited", "Has creado muchas conversaciones seguidas");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const now = Date.now();
        if (b.username) {
          const t = await byName(b.username); if (!t) return fail(404, "not_found", "Ese usuario no existe");
          const key = pairKey(me.id, t.id).join(":"), ex = await env.DB.prepare("SELECT id FROM nv_convs WHERE direct_key=?").bind(key).first();
          if (ex) return out({ conversation: { id: ex.id } });
          const er = await canMessage(env, me, t); if (er) return fail(er[0], er[1], er[2]);
          const id = crypto.randomUUID();
          await env.DB.batch([
            env.DB.prepare("INSERT INTO nv_convs (id,kind,direct_key,created_by,created_at,updated_at) VALUES (?,'direct',?,?,?,?)").bind(id, key, me.id, now, now),
            env.DB.prepare("INSERT INTO nv_conv_members (conv_id,user_id,role,joined_at) VALUES (?,?,'member',?)").bind(id, me.id, now), env.DB.prepare("INSERT INTO nv_conv_members (conv_id,user_id,role,joined_at) VALUES (?,?,'member',?)").bind(id, t.id, now),
          ]);
          return out({ conversation: { id } }, 201);
        }
        const title = String(b.title || "").trim(), names = [...new Set((Array.isArray(b.members) ? b.members : []).map((x) => String(x).toLowerCase()))].filter((x) => x !== me.username);
        if (title.length < 1 || title.length > 30) return fail(400, "invalid_title", "El grupo necesita un nombre de hasta 30 caracteres");
        if (names.length < 1 || names.length > 19) return fail(400, "invalid_members", "Un grupo necesita entre 2 y 20 personas");
        const users = [];
        for (const n of names) {
          const t = await byName(n); if (!t) return fail(404, "not_found", "No existe el usuario @" + n);
          const er = await canMessage(env, me, t); if (er) return fail(er[0], er[1], "@" + n + ": " + er[2]);
          users.push(t);
        }
        const id = crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO nv_convs (id,kind,title,created_by,created_at,updated_at) VALUES (?,'group',?,?,?,?)").bind(id, title, me.id, now, now),
          env.DB.prepare("INSERT INTO nv_conv_members (conv_id,user_id,role,joined_at) VALUES (?,?,'admin',?)").bind(id, me.id, now),
          ...users.map((t) => env.DB.prepare("INSERT INTO nv_conv_members (conv_id,user_id,role,joined_at) VALUES (?,?,'member',?)").bind(id, t.id, now)),
        ]);
        return out({ conversation: { id } }, 201);
      }
      if ((mt = p.match(/^\/api\/conversations\/([0-9a-f-]{36})\/messages$/)) && m === "GET") {
        const c = await memberOf(mt[1]); if (!c) return fail(404, "not_found", "La conversación no existe");
        const mem = await membersOf(c.id), others = mem.filter((x) => x.id !== me.id);
        if (c.kind === "direct" && others[0] && (await blockedPair(others[0].id))) return fail(404, "not_found", "La conversación no existe");
        const before = Number(url.searchParams.get("before")) || null, after = Number(url.searchParams.get("after")) || null;
        const { results } = await env.DB.prepare("SELECT m.id,m.sender_id,m.body,m.post_id,m.created_at,m.deleted,u.username,u.display_name,pr.avatar_id FROM nv_messages m JOIN nv_users u ON u.id=m.sender_id LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE m.conv_id=?1 AND (?2 IS NULL OR m.created_at<?2) AND (?3 IS NULL OR m.created_at>?3) ORDER BY m.created_at DESC LIMIT 40").bind(c.id, before, after).all();
        const messages = [];
        for (const r of results) {
          const rest = mem.filter((x) => x.id !== r.sender_id), readBy = rest.filter((x) => x.last_read_at >= r.created_at).length;
          messages.push({ id: r.id, username: r.username, display_name: r.display_name, avatar_id: r.avatar_id || null, mine: r.sender_id === me.id, body: r.deleted ? "" : r.body, deleted: !!r.deleted, created_at: r.created_at,
            post: !r.deleted && r.post_id ? ((await listPosts(env, me, { id: r.post_id }))[0] || { unavailable: true }) : null, read: rest.length > 0 && readBy === rest.length, read_by: readBy });
        }
        return out({ conversation: { id: c.id, kind: c.kind, title: c.kind === "direct" ? (others[0] ? others[0].display_name : "Conversación") : c.title, is_admin: c.role === "admin",
          members: mem.map((x) => ({ username: x.username, display_name: x.display_name, avatar_id: x.avatar_id || null, role: x.role })), with: c.kind === "direct" && others[0] ? { username: others[0].username, avatar_id: others[0].avatar_id || null } : null },
          streak: c.kind === "direct" && others[0] ? await streakFor(others[0].id) : null, messages });
      }
      if ((mt = p.match(/^\/api\/conversations\/([0-9a-f-]{36})\/messages$/)) && m === "POST") {
        const c = await memberOf(mt[1]); if (!c) return fail(404, "not_found", "La conversación no existe");
        if (!(await limit(env, "msg:" + me.id, 200, 3600))) return fail(429, "rate_limited", "Has enviado muchos mensajes seguidos");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const text = String(b.body || "").trim(), pid = b.post_id ? String(b.post_id) : null;
        if ((!text && !pid) || text.length > 1000) return fail(400, "invalid_body", "Escribe un mensaje de hasta 1000 caracteres");
        if (pid && !(UUID.test(pid) && (await visiblePost(env, me, pid)))) return fail(404, "not_found", "La publicación no existe");
        const mem = await membersOf(c.id), others = mem.filter((x) => x.id !== me.id);
        if (c.kind === "direct") {
          const t = others[0]; if (!t) return fail(409, "alone", "La otra persona ya no está en la conversación");
          const er = await canMessage(env, me, { id: t.id, birth_year: (await env.DB.prepare("SELECT birth_year FROM nv_users WHERE id=?").bind(t.id).first()).birth_year });
          if (er) return fail(er[0], er[1], er[2]);
        }
        const id = crypto.randomUUID(), now = Date.now();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO nv_messages (id,conv_id,sender_id,body,post_id,created_at) VALUES (?,?,?,?,?,?)").bind(id, c.id, me.id, text, pid, now),
          env.DB.prepare("UPDATE nv_convs SET updated_at=? WHERE id=?").bind(now, c.id), env.DB.prepare("UPDATE nv_conv_members SET last_read_at=? WHERE conv_id=? AND user_id=?").bind(now, c.id, me.id),
        ]);
        const streak = c.kind === "direct" ? await touchStreak(env, me.id, others[0].id, now) : null;
        return out({ message: { id, mine: true, body: text, created_at: now, post: pid ? ((await listPosts(env, me, { id: pid }))[0] || null) : null, read: false, read_by: 0, deleted: false }, streak }, 201);
      }
      if ((mt = p.match(/^\/api\/conversations\/([0-9a-f-]{36})\/read$/)) && m === "POST") {
        if (!(await memberOf(mt[1]))) return fail(404, "not_found", "La conversación no existe");
        await env.DB.prepare("UPDATE nv_conv_members SET last_read_at=? WHERE conv_id=? AND user_id=?").bind(Date.now(), mt[1], me.id).run();
        return out({ ok: true });
      }
      if ((mt = p.match(/^\/api\/messages\/([0-9a-f-]{36})$/)) && m === "DELETE") {
        const r = await env.DB.prepare("UPDATE nv_messages SET deleted=1, body='', post_id=NULL WHERE id=? AND sender_id=?").bind(mt[1], me.id).run();
        return r.meta.changes ? out({ ok: true }) : fail(404, "not_found", "El mensaje no existe o no es tuyo");
      }
      if ((mt = p.match(/^\/api\/conversations\/([0-9a-f-]{36})$/)) && m === "PATCH") {
        const c = await memberOf(mt[1]);
        if (!c || c.kind !== "group") return fail(404, "not_found", "El grupo no existe");
        if (c.role !== "admin") return fail(403, "not_admin", "Solo quien administra el grupo puede cambiarlo");
        const b = await readBody(req); if (!b) return fail(400, "bad_request", "Solicitud no válida");
        const title = b.title === undefined ? c.title : String(b.title).trim();
        if (title.length < 1 || title.length > 30) return fail(400, "invalid_title", "El grupo necesita un nombre de hasta 30 caracteres");
        const mem = await membersOf(c.id), add = [], now = Date.now();
        for (const n of [...new Set((Array.isArray(b.add) ? b.add : []).map((x) => String(x).toLowerCase()))]) {
          if (mem.some((x) => x.username === n)) continue;
          const t = await byName(n); if (!t) return fail(404, "not_found", "No existe el usuario @" + n);
          const er = await canMessage(env, me, t); if (er) return fail(er[0], er[1], "@" + n + ": " + er[2]);
          add.push(t);
        }
        if (mem.length + add.length > 20) return fail(400, "too_many", "Un grupo admite hasta 20 personas");
        const rem = (Array.isArray(b.remove) ? b.remove : []).map((x) => String(x).toLowerCase()).filter((x) => x !== me.username && mem.some((y) => y.username === x));
        await env.DB.batch([
          env.DB.prepare("UPDATE nv_convs SET title=? WHERE id=?").bind(title, c.id),
          ...add.map((t) => env.DB.prepare("INSERT OR IGNORE INTO nv_conv_members (conv_id,user_id,role,joined_at) VALUES (?,?,'member',?)").bind(c.id, t.id, now)),
          ...rem.map((n) => env.DB.prepare("DELETE FROM nv_conv_members WHERE conv_id=? AND user_id=(SELECT id FROM nv_users WHERE username=?)").bind(c.id, n)),
        ]);
        return out({ ok: true });
      }
      if ((mt = p.match(/^\/api\/conversations\/([0-9a-f-]{36})\/leave$/)) && m === "POST") {
        const c = await memberOf(mt[1]);
        if (!c || c.kind !== "group") return fail(404, "not_found", "El grupo no existe");
        await env.DB.prepare("DELETE FROM nv_conv_members WHERE conv_id=? AND user_id=?").bind(c.id, me.id).run();
        const left = await membersOf(c.id);
        if (!left.length) await env.DB.batch([env.DB.prepare("DELETE FROM nv_messages WHERE conv_id=?").bind(c.id), env.DB.prepare("DELETE FROM nv_convs WHERE id=?").bind(c.id)]);
        else if (c.role === "admin" && !left.some((x) => x.role === "admin")) await env.DB.prepare("UPDATE nv_conv_members SET role='admin' WHERE conv_id=? AND user_id=?").bind(c.id, left[0].id).run();
        return out({ ok: true });
      }

      // ---- Rachas compartidas (opcionales; descansar nunca las castiga)
      const streakRow = async (otherId) => { const [a, b] = pairKey(me.id, otherId); return env.DB.prepare("SELECT * FROM nv_streaks WHERE user_a=? AND user_b=?").bind(a, b).first(); };
      if (p === "/api/streaks" && m === "GET") {
        const { results } = await env.DB.prepare("SELECT * FROM nv_streaks WHERE user_a=?1 OR user_b=?1 ORDER BY count DESC, created_at DESC").bind(me.id).all();
        const today = dayOf(Date.now()), list = [];
        for (const s of results) {
          const oid = s.user_a === me.id ? s.user_b : s.user_a, u = await env.DB.prepare("SELECT u.username,u.display_name,pr.avatar_id FROM nv_users u LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE u.id=?").bind(oid).first();
          if (!u || (await blockedPair(oid))) continue;
          list.push({ with: { username: u.username, display_name: u.display_name, avatar_id: u.avatar_id || null }, status: s.status, proposed_by_me: s.proposed_by === me.id, count: s.count, best: s.best, total_days: s.total_days, paused: !!s.paused,
            me_today: (me.id === s.user_a ? s.a_last : s.b_last) === today, they_today: (me.id === s.user_a ? s.b_last : s.a_last) === today });
        }
        return out({ streaks: list });
      }
      if (p === "/api/streaks" && m === "POST") {
        const b = await readBody(req), t = b && (await byName(b.username));
        if (!t) return fail(404, "not_found", "Ese usuario no existe");
        const er = await canMessage(env, me, t); if (er) return fail(er[0], er[1], er[2]);
        const ex = await streakRow(t.id);
        if (ex) {
          if (ex.status === "pending" && ex.proposed_by !== me.id) { await env.DB.prepare("UPDATE nv_streaks SET status='active' WHERE id=?").bind(ex.id).run(); return out({ state: "active" }); }
          return out({ state: ex.status });
        }
        if ((await env.DB.prepare("SELECT COUNT(*) AS n FROM nv_streaks WHERE user_a=?1 OR user_b=?1").bind(me.id).first()).n >= 10) return fail(400, "too_many", "Puedes tener hasta 10 rachas");
        const [a, c] = pairKey(me.id, t.id);
        await env.DB.prepare("INSERT INTO nv_streaks (id,user_a,user_b,proposed_by,created_at) VALUES (?,?,?,?,?)").bind(crypto.randomUUID(), a, c, me.id, Date.now()).run();
        return out({ state: "pending" }, 201);
      }
      if ((mt = p.match(/^\/api\/streaks\/([A-Za-z0-9_.]{3,24})\/(accept|pause)$/)) && m === "POST") {
        const t = await byName(mt[1]), s = t && (await streakRow(t.id));
        if (!s) return fail(404, "not_found", "No hay una racha con esa persona");
        if (mt[2] === "accept") {
          if (s.status !== "pending" || s.proposed_by === me.id) return fail(404, "not_found", "No hay una solicitud de esa persona");
          await env.DB.prepare("UPDATE nv_streaks SET status='active' WHERE id=?").bind(s.id).run();
          return out({ state: "active" });
        }
        const b = await readBody(req);
        if (s.status !== "active") return fail(409, "not_active", "La racha todavía no está activa");
        await env.DB.prepare("UPDATE nv_streaks SET paused=? WHERE id=?").bind(b && b.paused ? 1 : 0, s.id).run();
        return out({ paused: !!(b && b.paused) });
      }
      if ((mt = p.match(/^\/api\/streaks\/([A-Za-z0-9_.]{3,24})$/)) && m === "DELETE") {
        const t = await byName(mt[1]);
        if (t) { const [a, c] = pairKey(me.id, t.id); await env.DB.prepare("DELETE FROM nv_streaks WHERE user_a=? AND user_b=?").bind(a, c).run(); }
        return out({ ok: true });
      }
      if (p === "/api/badges" && m === "GET") {
        const { results } = await env.DB.prepare("SELECT code,tier,earned_at FROM nv_badges WHERE user_id=? ORDER BY earned_at").bind(me.id).all();
        const best = (await env.DB.prepare("SELECT COALESCE(MAX(best),0) AS n FROM nv_streaks WHERE user_a=?1 OR user_b=?1").bind(me.id).first()).n, have = new Set(results.map((r) => r.code));
        return out({ badges: results, catalog: STREAK_BADGES.map(([n, tier, name]) => ({ code: "streak_" + n, category: "rachas", tier, name, need: n, progress: Math.min(best, n), earned: have.has("streak_" + n) })) });
      }

      // ---- Perfiles ajenos, búsqueda y tendencias
      if ((mt = p.match(/^\/api\/users\/([A-Za-z0-9_.]{3,24})$/)) && m === "GET") {
        const u = await env.DB.prepare(PROFILE + " WHERE u.username=?").bind(mt[1].toLowerCase()).first();
        if (!u || (u.id !== me.id && (await env.DB.prepare("SELECT 1 FROM nv_blocks WHERE (blocker=? AND blocked=?) OR (blocker=? AND blocked=?)").bind(me.id, u.id, u.id, me.id).first()))) return fail(404, "not_found", "Ese usuario no existe");
        const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM nv_posts WHERE user_id=? AND (visibility='public' OR user_id=?)").bind(u.id, me.id).first();
        const see = await canSeeUser(env, me, u.id);
        const pt = see ? await env.DB.prepare("SELECT species,name,xp,accessory,energy FROM nv_pets WHERE user_id=? AND status='hatched' AND show_on_profile=1").bind(u.id).first() : null;
        const one = async (sql, ...a) => (await env.DB.prepare(sql).bind(...a).first());
        const fc = (await one("SELECT COUNT(*) AS n FROM nv_follows WHERE followee_id=? AND status='accepted'", u.id)).n, gc = (await one("SELECT COUNT(*) AS n FROM nv_follows WHERE follower_id=? AND status='accepted'", u.id)).n;
        const rel = await one("SELECT status FROM nv_follows WHERE follower_id=? AND followee_id=?", me.id, u.id), back = await one("SELECT 1 AS x FROM nv_follows WHERE follower_id=? AND followee_id=? AND status='accepted'", u.id, me.id);
        const priv = await one("SELECT private_account AS p FROM nv_privacy WHERE user_id=?", u.id);
        return out({ user: { ...pub(u), created_at: u.created_at, post_count: cnt.n, is_me: u.id === me.id, is_private: !!(priv && priv.p), can_see: see, followers_count: fc, following_count: gc, follows_me: !!back, follow_state: u.id === me.id ? "self" : rel ? (rel.status === "accepted" ? "following" : "requested") : "none", pet: pt ? { species: pt.species, name: pt.name, stage: stageOf(pt.xp), accessory: pt.accessory, energy: pt.energy } : null } });
      }
      if (p === "/api/search" && m === "GET") {
        if (!(await limit(env, "search:" + me.id, 60, 60))) return fail(429, "rate_limited", "Demasiadas búsquedas seguidas");
        const q = (url.searchParams.get("q") || "").trim().slice(0, 50);
        if (!q) return out({ users: [], posts: [] });
        const uq = q.replace(/^@/, ""), like = (s) => "%" + s.replace(/[\\%_]/g, "\\$&") + "%";
        const { results: users } = await env.DB.prepare(
          "SELECT u.username,u.display_name,u.bio,pr.avatar_id FROM nv_users u LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE (u.username LIKE ?1 ESCAPE '\\' OR u.display_name LIKE ?1 ESCAPE '\\') AND NOT EXISTS (SELECT 1 FROM nv_blocks bk WHERE (bk.blocker=?3 AND bk.blocked=u.id) OR (bk.blocker=u.id AND bk.blocked=?3)) ORDER BY (u.username=?2) DESC, u.username LIMIT 10"
        ).bind(like(uq), uq.toLowerCase(), me.id).all();
        return out({ users: users.map((u) => ({ ...u, avatar_id: u.avatar_id || null })), posts: await listPosts(env, me, { q: like(q), pub: true }) });
      }
      if (p === "/api/trending" && m === "GET") {
        const { results } = await env.DB.prepare(`SELECT body FROM nv_posts WHERE visibility='public' AND created_at>? AND NOT ${PRIVATE("nv_posts.user_id")} ORDER BY created_at DESC LIMIT 500`).bind(Date.now() - 7 * 864e5).all();
        const count = {};
        for (const r of results) for (const t of new Set((r.body.toLowerCase().match(/#[\p{L}\p{N}_]{2,30}/gu) || []))) count[t] = (count[t] || 0) + 1;
        return out({ tags: Object.entries(count).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([tag, n]) => ({ tag, count: n })) });
      }
      return fail(404, "not_found", "Ruta no encontrada");
    } catch (e) {
      console.error(e);
      return fail(500, "server_error", "Error del servidor");
    }
  },
};
