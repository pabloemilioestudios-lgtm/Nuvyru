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
const PROFILE = "SELECT u.id,u.username,u.display_name,u.bio,u.created_at,pr.avatar_id,pr.banner_id,pr.website,pr.location,pr.pronouns,pr.accent FROM nv_users u LEFT JOIN nv_profiles pr ON pr.user_id=u.id";
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
const POSTS_SQL = `SELECT p.id,p.body,p.visibility,p.created_at,u.username,u.display_name,pr.avatar_id,
 (SELECT COUNT(*) FROM nv_likes l WHERE l.post_id=p.id) AS like_count,
 EXISTS(SELECT 1 FROM nv_likes l WHERE l.post_id=p.id AND l.user_id=?1) AS liked,
 EXISTS(SELECT 1 FROM nv_saves s WHERE s.post_id=p.id AND s.user_id=?1) AS saved
 FROM nv_posts p JOIN nv_users u ON u.id=p.user_id LEFT JOIN nv_profiles pr ON pr.user_id=u.id
 WHERE (p.visibility='public' OR p.user_id=?1) AND (?2 IS NULL OR u.username=?2) AND (?3 IS NULL OR p.created_at<?3)
 AND (?4 IS NULL OR EXISTS(SELECT 1 FROM nv_post_media pm JOIN nv_media m ON m.id=pm.media_id WHERE pm.post_id=p.id AND (?4='media' OR m.kind=?4)))
 AND (?5 IS NULL OR p.body LIKE ?5 ESCAPE '\\') AND (?6=0 OR p.visibility='public') AND (?7 IS NULL OR p.id=?7)
 ORDER BY p.created_at DESC LIMIT 30`;
async function listPosts(env, me, o = {}) {
  const { results } = await env.DB.prepare(POSTS_SQL).bind(me.id, o.user ?? null, o.before ?? null, o.kind ?? null, o.q ?? null, o.pub ? 1 : 0, o.id ?? null).all();
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

const PLANNED = { "/api/comments": 3, "/api/follows": 3, "/api/notifications": 3, "/api/messages": 4, "/api/badges": 5, "/api/orya": 6, "/api/live": 7 };

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
          kind: ["image", "video", "media"].includes(kind) ? kind : null, pub: sp.get("public") === "1",
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
        const ok = await env.DB.prepare("SELECT id FROM nv_posts WHERE id=? AND (visibility='public' OR user_id=?)").bind(mt[1], me.id).first();
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
          ...files.map((f) => env.DB.prepare("DELETE FROM nv_media WHERE id=?").bind(f.id)),
          env.DB.prepare("DELETE FROM nv_posts WHERE id=?").bind(mt[1]),
        ]);
        return out({ ok: true });
      }

      // ---- Perfiles ajenos, búsqueda y tendencias
      if ((mt = p.match(/^\/api\/users\/([A-Za-z0-9_.]{3,24})$/)) && m === "GET") {
        const u = await env.DB.prepare(PROFILE + " WHERE u.username=?").bind(mt[1].toLowerCase()).first();
        if (!u) return fail(404, "not_found", "Ese usuario no existe");
        const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM nv_posts WHERE user_id=? AND (visibility='public' OR user_id=?)").bind(u.id, me.id).first();
        const pt = await env.DB.prepare("SELECT species,name,xp,accessory,energy FROM nv_pets WHERE user_id=? AND status='hatched' AND show_on_profile=1").bind(u.id).first();
        return out({ user: { ...pub(u), created_at: u.created_at, post_count: cnt.n, is_me: u.id === me.id, pet: pt ? { species: pt.species, name: pt.name, stage: stageOf(pt.xp), accessory: pt.accessory, energy: pt.energy } : null } });
      }
      if (p === "/api/search" && m === "GET") {
        if (!(await limit(env, "search:" + me.id, 60, 60))) return fail(429, "rate_limited", "Demasiadas búsquedas seguidas");
        const q = (url.searchParams.get("q") || "").trim().slice(0, 50);
        if (!q) return out({ users: [], posts: [] });
        const uq = q.replace(/^@/, ""), like = (s) => "%" + s.replace(/[\\%_]/g, "\\$&") + "%";
        const { results: users } = await env.DB.prepare(
          "SELECT u.username,u.display_name,u.bio,pr.avatar_id FROM nv_users u LEFT JOIN nv_profiles pr ON pr.user_id=u.id WHERE u.username LIKE ?1 ESCAPE '\\' OR u.display_name LIKE ?1 ESCAPE '\\' ORDER BY (u.username=?2) DESC, u.username LIMIT 10"
        ).bind(like(uq), uq.toLowerCase()).all();
        return out({ users: users.map((u) => ({ ...u, avatar_id: u.avatar_id || null })), posts: await listPosts(env, me, { q: like(q), pub: true }) });
      }
      if (p === "/api/trending" && m === "GET") {
        const { results } = await env.DB.prepare("SELECT body FROM nv_posts WHERE visibility='public' AND created_at>? ORDER BY created_at DESC LIMIT 500").bind(Date.now() - 7 * 864e5).all();
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
